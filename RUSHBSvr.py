import time
import select
import socket
import threading


VERSION = 2
PACKET_LENGTH = 1472


class MasterController:
    def __init__(self):
        self.sock = initialise_socket()
        self.lock = threading.Lock()
        self.clients_and_packets = dict()  # client_address --> [[packets_incoming], [packets_outgoing]]
        self.clients_to_close = list()
        self.block_list = list()
        self.invalid_packet_log = list()

    def add_to_invalid_packet_log(self, time_recv):
        """
        Inserts the time an invalid packet was received to the invalid_packet_log.
        Freezes the program  for 10 seconds if 30 invalid packets are received within 5 seconds.
        :param time_recv: The time the invalid packet was received.
        """
        self.lock.acquire()
        self.invalid_packet_log.insert(0, time_recv)
        if len(self.invalid_packet_log) < 30:
            self.lock.release()
            return
        if self.invalid_packet_log[0] - self.invalid_packet_log[29] < 5:
            # freeze for 10 seconds
            start = time.time()
            while time.time() - start < 10:
                pass
            self.invalid_packet_log.clear()
        self.lock.release()

    def block(self, client):
        """
        Blocks this client indefinitely by adding it to the block_list.
        :param client: To be blocked.
        """
        self.lock.acquire()
        self.block_list.append(client)
        del self.clients_and_packets[client]
        self.lock.release()

    def add_outgoing(self, client, message: bytes):
        """
        Adds the given message to the given client's pending outbox.
        Messages in these outboxes are routinely sent by the send_all() method.
        :param client: To send the message to.
        :param message: To send to the client.
        :return:
        """
        self.lock.acquire()
        inbox_and_outbox = self.clients_and_packets.get(client)
        outbox = inbox_and_outbox[1]
        outbox.append(message)
        self.lock.release()

    def send_all(self):
        """
        Sends all packets in the pending-outboxes of all clients.
        """
        self.lock.acquire()
        for address, inbox_and_outbox in self.clients_and_packets.items():
            outbox = inbox_and_outbox[1]
            for packet in outbox:
                self.sock.sendto(packet, address)
            outbox.clear()
        self.lock.release()

    def get_from_receive_pool(self, client):
        """
        Pops the earliest message received in the given client's inbox.
        :param client: To get the received message from.
        :return: The earliest unread message from the client, or an empty byte string if none found.
        """
        self.lock.acquire()
        inbox_and_outbox = self.clients_and_packets.get(client)
        inbox = inbox_and_outbox[0]
        if len(inbox) == 0:
            self.lock.release()
            return b''
        message = inbox.pop(0)
        self.lock.release()
        return message

    def poll_socket(self):
        """
        Checks the socket for incoming messages to process.
        Messages from blocked clients are ignored.
        If the message is from a new client, constructs an inbox and outbox for that client, and gives it a new thread.
        """
        self.lock.acquire()
        ready = select.select([self.sock], [], [], 0)
        if not ready[0]:
            # socket is empty
            self.lock.release()
            return
        # socket is not empty; receive message
        data, address = self.sock.recvfrom(PACKET_LENGTH)
        # check if it's from a recipient we've blocked
        if address in self.block_list:
            # ignore
            self.lock.release()
            return
        # check if the address is new
        if address in self.clients_and_packets.keys():
            # address is not new, add the received data to the existing client's inbox
            inbox_and_outbox = self.clients_and_packets.get(address)
            inbox = inbox_and_outbox[0]
            inbox.append(data)
        else:
            # address is new, make an inbox and outbox for this client and start it on a new thread.
            inbox = [data]
            outbox = []
            self.clients_and_packets[address] = [inbox, outbox]
            thread = threading.Thread(target=handler, args=(address,))
            thread.start()
        self.lock.release()

    def close_dead_clients(self):
        """
        Client threads can tell the MasterController with add_to_dead_clients(client) that they are about to close.
        This method clears all data associated with such clients, essentially closing the connection.
        """
        self.lock.acquire()
        for address in self.clients_to_close:
            del self.clients_and_packets[address]
        self.clients_to_close.clear()
        self.lock.release()

    def add_to_dead_clients(self, client):
        """
        This method is called by client threads which are about to close.
        It adds those clients to a list which contains clients to close connections with, via close_dead_clients().
        :param client: To close a connection with.
        """
        self.lock.acquire()
        self.clients_to_close.append(client)
        self.lock.release()


master_controller = MasterController()


class Flag:
    """
    Flags are used by Packet objects. Their respective values represent their positions in the flags header.
    """
    ACK, NAK, GET, DAT, FIN, CHK, ENC = range(0, 7)


class Packet:
    """
    Represents data contained in a RUSHB packet.
    """
    def __init__(self, seq: int, ack: int, chk: int, flg: list, pay: str):
        """
        :param seq: Sequence number of this packet.
        :param ack: Acknowledgement number of this packet.
        :param chk: Checksum of this packet, or 0 if none.
        :param flg: List of Flags to be set in this packet (e.g. Flag.ACK, Flag.FIN).
        :param pay: Payload of this packet, in ascii.
        """
        self.seq = seq
        self.ack = ack
        self.chk = chk
        self.flg = [0, 0, 0, 0, 0, 0, 0]
        for i in flg:
            self.flg[i] = 1
        self.pay = pay

    def set_flags(self, flags):
        for flg in flags:
            self.flg[flg] = 1


def main():
    while True:
        master_controller.poll_socket()
        master_controller.send_all()
        master_controller.close_dead_clients()
        time.sleep(0.1)


def initialise_socket():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.bind(('localhost', 0))
    print(sock.getsockname()[1], flush=True)
    return sock


def handler(client):
    invalid_packet_log = []  # contains the times of all invalid or GET packets received
    additional_flags = []
    try:
        get_packet, client = receive_get_request(client, invalid_packet_log)
        # record whether client requests encryption or checksum
        for additional_flag in [Flag.ENC, Flag.CHK]:
            if get_packet.flg[additional_flag]:
                additional_flags.append(additional_flag)
        # partition the requested file into packet segments
        packets = partition_file(get_packet.pay, additional_flags)
        num_packets = len(packets)
        seq_num = num_packets + 1
        # send each packet, retransmitting if NAK is received
        expected_seq = 2
        for i in range(0, num_packets):
            response_pkt = send_dat_receive_ack(client, packets[i], additional_flags, expected_seq,
                                                invalid_packet_log)
            expected_seq = response_pkt.seq + 1
        # all packets sent; close connection
        close_connection(client, seq_num, additional_flags, invalid_packet_log)
    except DDOSException:
        block_client(client)
    except (FileNotFoundError, UnicodeEncodeError):
        # invalid file name, close connection
        close_connection(client, 1, additional_flags, invalid_packet_log)


def partition_file(filename, additional_flags):
    """
    Creates a list of packets containing the file, partitioned into appropriately-sized chunks.
    :param filename: Of the file to be partitioned.
    :param additional_flags: Optional flags such as Flag.ENC and Flag.CHK to be set.
    :return: A list packets representing the partitioned file.
    """
    with open(filename, 'r') as file:
        packets = []
        segment = file.read(PACKET_LENGTH - 8)
        seq_num = 1
        while segment != '':  # this will not send packets with empty files
            packet = Packet(seq_num, 0, 0, [Flag.DAT], segment)
            packet.set_flags(additional_flags)
            packets.append(packet)
            segment = file.read(PACKET_LENGTH - 8)
            seq_num += 1
    return packets


def close_connection(client, seq_num, additional_flags, invalid_packet_log):
    """
    Executes the three-way handshake to close the connection with the client.
    :param client: To end the connection with.
    :param seq_num: Of the first [FIN] packet to send.
    :param additional_flags: Optional flags such as Flag.ENC and Flag.CHK to be set.
    :param invalid_packet_log: The log containing times of all invalid or GET packets received by this client.
    :return:
    """
    flags = [Flag.FIN]
    for flg in additional_flags:
        flags.append(flg)
    packet = Packet(seq_num, 0, 0, flags, '')
    response_pkt = send_fin_receive_fin_ack(client, packet, additional_flags, invalid_packet_log)
    flags.append(Flag.ACK)
    packet = Packet(seq_num + 1, response_pkt.seq, 0, flags, '')
    master_controller.add_outgoing(client, packet_to_bytes(packet))
    master_controller.add_to_dead_clients(client)


def block_client(client):
    """
    Blocks this client indefinitely.
    :param client: To be blocked.
    """
    master_controller.block(client)
    # clients need to be blocked before a potential system-wide freeze occurs due to too many invalid packets,
    # therefore, the time of the final invalid packet is logged to the MasterController here, immediately after blocking
    master_controller.add_to_invalid_packet_log(time.time())


def receive_get_request(client, invalid_packet_log):
    """
    Waits to receive a valid GET request, and ignores invalid requests.
    :param client: Of the client to receive the request from.
    :param invalid_packet_log: A log containing all invalid or GET requests from this client.
    :return: A tuple of (received, address), containing respectively the packet received and the address of the client.
    """
    while True:
        data = receive_packet(client)
        add_to_history(time.time(), invalid_packet_log)
        master_controller.add_to_invalid_packet_log(time.time())
        try:
            received = bytes_to_packet(data)
            if received.seq != 1:
                continue
            if verify_flags_for_get_packet(received.flg):
                return received, client
        except InvalidChecksumException:
            continue


def add_to_history(time_received: float, invalid_packet_log: list):
    invalid_packet_log.insert(0, time_received)
    if len(invalid_packet_log) < 10:
        return
    if invalid_packet_log[0] - invalid_packet_log[9] <= 2:
        raise DDOSException


def send_fin_receive_fin_ack(client, packet: Packet, additional_flags, invalid_packet_log):
    timeout = 4
    time_left = 4
    while True:
        response, time_left = send_and_receive_helper(client, packet, timeout, time_left)
        try:
            response_pkt = bytes_to_packet(response)  # throws exception on bad checksum
            # ignore packets that are not valid ack/fins
            if not verify_flags_for_ack_fin_packet(response_pkt.flg, additional_flags):
                add_to_history(time.time(), invalid_packet_log)
                master_controller.add_to_invalid_packet_log(time.time())
                continue
            if response_pkt.ack != packet.seq:
                add_to_history(time.time(), invalid_packet_log)
                master_controller.add_to_invalid_packet_log(time.time())
                continue
            # upon receiving a nak, reset the timer and resend the packet
            if response_pkt.flg[Flag.NAK]:
                time_left = 4
                continue
            # valid ack received
            return response_pkt
        except InvalidChecksumException:
            add_to_history(time.time(), invalid_packet_log)
            master_controller.add_to_invalid_packet_log(time.time())
            continue


def send_dat_receive_ack(client, packet: Packet, additional_flags, expected_seq, invalid_packet_log):
    """
    Ensures the packet returned contains a valid checksum.
    Ensures the packet returned is a valid [ACK] response.
    Re-sends on timeout (4 seconds).
    Re-sends on receiving a NAK with a reset timeout.
    Ignores all responses that do not contain a valid checksum or are not valid acks or naks.
    """
    timeout = 4
    time_left = 4
    while True:
        response, time_left = send_and_receive_helper(client, packet, timeout, time_left)
        try:
            response_pkt = bytes_to_packet(response)  # throws exception on bad checksum
            # ignore packets that are not valid acks or naks
            if not verify_flags_for_dat_ack_packet(response_pkt.flg, additional_flags):
                add_to_history(time.time(), invalid_packet_log)
                master_controller.add_to_invalid_packet_log(time.time())
                continue
            if response_pkt.seq != expected_seq:
                add_to_history(time.time(), invalid_packet_log)
                master_controller.add_to_invalid_packet_log(time.time())
                continue
            if response_pkt.ack != packet.seq:
                add_to_history(time.time(), invalid_packet_log)
                master_controller.add_to_invalid_packet_log(time.time())
                continue
            # upon receiving a nak, reset the timer and resend the packet
            if response_pkt.flg[Flag.NAK]:
                expected_seq += 1
                time_left = 4
                continue
            # valid ack received
            return response_pkt
        except InvalidChecksumException:
            add_to_history(time.time(), invalid_packet_log)
            master_controller.add_to_invalid_packet_log(time.time())
            continue


def send_and_receive_helper(address, packet: Packet, timeout, first_timeout):
    """
    Continuously sends the specified packet to the specified address, repeating with each timeout.
    :return: A tuple of the response (in bytes) and time left on the timer.
    """
    encoded = packet_to_bytes(packet)
    master_controller.add_outgoing(address, encoded)
    start = time.time()
    data = receive_packet_with_timeout(address, first_timeout)
    while not data:
        # timeout, resend without acknowledgement and reset timer
        packet.ack = 0
        packet.flg[Flag.ACK] = 0
        encoded = packet_to_bytes(packet)
        master_controller.add_outgoing(address, encoded)
        start = time.time()
        data = receive_packet_with_timeout(address, first_timeout)
    # received response
    time_left = timeout - (time.time() - start)
    return data, time_left


def bytes_to_packet(data: bytes):
    """
    Verifies checksums and nothing more. Throws InvalidChecksumException on bad checksum.
    """
    # decode header
    seq = int.from_bytes(data[0:2], 'big')
    ack = int.from_bytes(data[2:4], 'big')
    chk = int.from_bytes(data[4:6], 'big')
    flg = []
    for i in range(0, 7):
        if data[6] & (1 << 7 - i):
            flg.append(i)
    # compute and verify checksum if necessary
    if Flag.CHK in flg:
        checksum = compute_checksum(data[8:])
        if checksum != chk:
            raise InvalidChecksumException
    # decode payload
    pay = ''
    for byte in data[8:]:
        if byte != 0:
            pay += chr(byte)
    # decrypt payload if necessary
    if Flag.ENC in flg:
        pay = decrypt(pay)
    # create packet
    return Packet(seq, ack, chk, flg, pay)


def packet_to_bytes(packet: Packet):
    # encrypt payload if necessary
    pay_str = packet.pay
    if packet.flg[Flag.ENC]:
        pay_str = encrypt(pay_str)
    # encode payload
    pay = b''
    for c in pay_str:
        pay += ord(c).to_bytes(1, 'big')
    # compute checksum if necessary
    chk = 0
    if packet.flg[Flag.CHK]:
        chk = compute_checksum(pay)
    # encode header
    seq = packet.seq.to_bytes(2, 'big')
    ack = packet.ack.to_bytes(2, 'big')
    chk = chk.to_bytes(2, 'big')
    flg = ''.join([str(i) for i in packet.flg]) + '0'
    flg = int(flg, 2).to_bytes(1, 'big')
    vrs = VERSION.to_bytes(1, 'big')
    # concatenate into one byte string
    data = seq + ack + chk + flg + vrs + pay
    assert len(data) <= PACKET_LENGTH  # for debugging
    data += (PACKET_LENGTH - len(data)) * b'\0'  # add padding to make the required PACKET_LENGTH bytes
    return data


def decrypt(msg: str):
    decrypted = ''
    for c in msg:
        i = ord(c)
        i = (i ** 15) % 249
        decrypted += chr(i)
    return decrypted


def encrypt(msg: str):
    encrypted = ''
    for c in msg:
        i = ord(c)
        i = (i ** 11) % 249
        encrypted += chr(i)
    return encrypted


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


def verify_flags_for_get_packet(flags):
    if not flags[Flag.GET]:
        return False
    for invalid_flag in [Flag.ACK, Flag.NAK, Flag.DAT, Flag.FIN]:
        if flags[invalid_flag]:
            return False
    return True


def verify_flags_for_dat_ack_packet(flags, additional_required):
    if not flags[Flag.DAT]:
        return False
    if not flags[Flag.ACK] and not flags[Flag.NAK]:
        return False
    for invalid_flag in [Flag.GET, Flag.FIN]:
        if flags[invalid_flag]:
            return False
    if Flag.ENC in additional_required and not flags[Flag.ENC]:
        return False
    if Flag.CHK in additional_required and not flags[Flag.CHK]:
        return False
    return True


def verify_flags_for_ack_fin_packet(flags, additional_required):
    if not flags[Flag.ACK] or not flags[Flag.FIN]:
        return False
    for invalid_flag in [Flag.GET, Flag.NAK, Flag.DAT]:
        if flags[invalid_flag]:
            return False
    if Flag.ENC in additional_required and not flags[Flag.ENC]:
        return False
    if Flag.CHK in additional_required and not flags[Flag.CHK]:
        return False
    return True


def receive_packet(address):
    while True:
        data = master_controller.get_from_receive_pool(address)
        time.sleep(0.1)
        if data:
            return data


def receive_packet_with_timeout(address, timeout):
    start = time.time()
    while time.time() - start < timeout:
        data = master_controller.get_from_receive_pool(address)
        time.sleep(0.1)
        if data:
            return data
    return b''


class InvalidChecksumException(Exception):
    pass


class DDOSException(Exception):
    pass


if __name__ == '__main__':
    main()
