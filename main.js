// Imports are constants because they doen't have to change their value
const udp = require('dgram') // -> used to create a socket ( supports both ipv4 and ipv6 )
// const int24 = require('int24') // -> used to read / write 24 bit integers

// Host and port used to bind the socket
const PORT = 19132
const HOST = "0.0.0.0"

// ID used in offline packets to identify the server
const ID = 6129484611666145821 // -> int63 random id (need to make it randomized)
const NAME = "MCPE;Pong Test;390;1.14.60;1;5;6129484611666145821;NodeScript;Creative;1;19132;19132;" // TODO: improve server name generation

// A vanilla SID: 10637029610827823494

// Map of connections (address -> string => to decide) to identify connected users
const connections = new Map()

// List (name => id) to identify offline packets
const OfflinePackets = {
	UnconnectedPing: 0x01,
	UnconnectedPong: 0x1c,

	OpenConnectionRequest1: 0x05,
	OpenConnectionReply1: 0x06,
	OpenConnectionRequest2: 0x07,
	OpenConnectionReply2: 0x08
}

// List (name => id) to identify flagged packets (not finished)
const BitFlags = {
	Valid: 0x80,
	Ack: 0x40,
	Nack: 0x20,
	Split: 0x10
}

// We use let because we need the socket variable just in this scope
const socket = udp.createSocket('udp4') // -> udp4 for ipv4 binding and ipv6 for ipv6

// Check if we get any error by binding the socket on the defined address and port
// íf yes, throw them
socket.on('error', function(error) {
	throw new Error(error)
})

// If everything is fine, get a log 
socket.on('listening', function() {
	let address = socket.address()
	console.log('Socket successfully bound on %s:%s!', address.address, address.port)
})

// Bind the socket 
socket.bind(PORT, HOST)

// Listen for packets
// msg -> Buffer instance (contains a buffer with packet data)
// rinfo -> RemoteInfo instance (contains info about the packet sender)
socket.on('message', function(msg, rinfo) {
	let found = connections.has(rinfo.address)

	if (!found) {
		// 8 bits => 1 byte
		let id = msg.readInt8() // -> this is the packet identifier

		// Handle properly every packet by its ID
		switch(id) {
			case OfflinePackets.UnconnectedPing:
				return handleUnconnectedPing(msg, rinfo)
			case OfflinePackets.OpenConnectionRequest1:
				return handleOpenConnectionRequest1(msg, rinfo)
			case OfflinePackets.OpenConnectionRequest2:
				return handleOpenConnectionRequest2(msg, rinfo)
			default:
				if (id & BitFlags.Valid == 0) {
					console.log('Unknown packet received: (%s): %s', id, msg)
				}	
		}
	} else {
		let conn = connections.get(rinfo.address)
		conn.receive(msg)
	}
})

function handleUnconnectedPing(msg, address) {
	let decodedPk = new UnconnectedPing(msg)
	decodedPk.read()
	let encodedPk = new UnconnectedPong(decodedPk.sendTimeStamp, ID, decodedPk.magic)
	encodedPk.write()
	socket.send(encodedPk.buffer, 0, encodedPk.buffer.length, address.port, address.address)
}

function handleOpenConnectionRequest1(msg, address) {
	let decodedPk = new OpenConnectionRequest1(msg)
	decodedPk.read()
	let encodedPk = new OpenConnectionReply1(ID, decodedPk.mtuSize)
	encodedPk.write()
	socket.send(encodedPk.buffer, 0, encodedPk.buffer.length, address.port, address.address)
}

function handleOpenConnectionRequest2(msg, address) {
	let decodedPk = new OpenConnectionRequest2(msg)
	decodedPk.read()
	let encodedPk = new OpenConnectionReply2(ID, address, decodedPk.mtuSize)
	encodedPk.write()
	socket.send(encodedPk.buffer, 0, encodedPk.buffer.length, address.port, address.address)

	let conn = new Connection(false, address, decodedPk.mtuSize, decodedPk.clientGUID)
	connections.set(address.address, conn)
}

// We need a binary class because with node buffer itself, is impossible to keep track of index
class Binary {

	// PERSONAL NOTES (used to increase buffer offset)
	// int 8 => 1 byte => boolean 
	// int16 => 2 bytes => short
	// int24 => 3 bytes => triad
	// int32 => 4 bytes => int
	// int64 => 8 bytes => long

	constructor(buffer = Buffer.alloc(0), offset = 0) {
		this.buffer = buffer
		this.offset = offset
	}

	writeByte(b) {
		let buffer = Buffer.alloc(1)
		buffer.writeUInt8(b)
		this.buffer = Buffer.concat([this.buffer, buffer])
		this.offset += 1
	}

	readByte() {
		return this.buffer[(this.offset += 1) - 1]
	}

	writeBoolean(b) {
		this.writeByte(b ? 1 : 0)
	}

	// Writes a signed 64 bit int
	writeLong(i) {
		let buffer = Buffer.alloc(8)
		buffer.fill(0)
		buffer.writeUInt32BE(i >> 8) // write the high order bits (shifted over)
		buffer.writeUInt32BE(i & 0x00ff, 4) // write the low order bits
		this.buffer = Buffer.concat([this.buffer, buffer])
		this.offset += 8
	}

	readLong() {
		return (this.buffer.readUInt32BE((this.offset += 4) - 4) << 8) + this.buffer.readUInt32BE((this.offset += 4) - 4)
	}

	// Writes a signed 16 bit int
	writeShort(s) {
		let buffer = Buffer.alloc(2)
		buffer.writeUInt16BE(s)
		this.buffer = Buffer.concat([this.buffer, buffer])
		this.offset += 2
	}

	readShort() {
		return this.buffer.readUInt16BE((this.offset += 2) - 2)
	}

	// Move to packet or offline packet class??
	writeString(s) {
		let len = Buffer.byteLength(s)
		this.writeShort(len)  // The game has the string length now, so he know how much he need to slice
		this.buffer = Buffer.concat([this.buffer, Buffer.from(s, 'utf-8')])
		this.offset += len
	}

	readLTriad() {
		return this.buffer.readUIntLE((this.offset += 3) - 3, 3)
	}

	writeLTriad(t) {
        let buffer = Buffer.alloc(3)
        buffer.writeUIntLE(t, 0, 3)
        this.buffer = Buffer.concat([this.buffer, buffer])
        this.offset += 3
    }
	
	readInt() {
        return this.buffer.readInt32BE((this.offset += 4) - 4)
    }

	writeInt(i) {
        let buffer = Buffer.alloc(4)
        buffer.writeInt32BE(i)
        this.buffer = Buffer.concat([this.buffer, buffer])
        this.offset += 4
    }
}

// Packet object containing the offset of the buffer and other stuff we may need
const PacketReliability = {
	Unreliable: 0,
	UnreliableSequenced: 1,
	Reliable: 2,
	ReliableOrdered: 3,
	ReliableSequenced: 4,
	UnreliableWithAckReceipt: 5,
	ReliableWithAckReceipt: 6,
	ReliableOrderedWithAckReceipt: 7
}
const MaxAcknowledgementPackets = 4096
const RecordTypes = {
	Range: 0,
	Single: 1
}
class Packet extends Binary {

	// Decodeds an encapsulated packet
	readDatagram() {
		let header = this.readByte()
		this.split = (header&BitFlags.Split) !== 0
		this.reliability = (header&224) >> 5
		let packetLength = this.readShort()
		packetLength >>= 3
		if (packetLength == 0) {
			// throw new Error("Packet length cannot be 0")
			// SHIT connected ping addicted... has 0 as short
		}

		if (this.reliable()) {
			this.messageIndex = this.readLTriad()
		}

		if (this.sequenced()) {
			this.sequenceIndex = this.readLTriad()
		}

		if (this.sequencedOrOrdered()) {
			this.orderIndex = this.readLTriad()
			this.readByte()  // skip order channel
		}

		if (this.split) {
			this.splitCount = this.readLong()
			this.splitIndex = this.readLong()
			this.splitID = this.readShort()
		}

		this.content = new Binary(this.buffer.slice(this.offset, this.offset + packetLength))
	}

	// Encapsulates a packet
	writeDatagram() {
		let header = this.reliability << 5
		if (this.split) {
			header |= BitFlags.Split
		}
		this.writeByte(header)	
		// this.content wtf is undefined
		this.writeShort((this.content.buffer.length) << 3)
		if (this.reliable()) {
			this.writeLTriad(this.messageIndex)
		}
		if (this.sequenced()) {
			this.writeLTriad(sequenceIndex)
		}
		if (this.sequencedOrOrdered()) {
			this.writeLTriad(this.orderIndex)
			this.writeByte(0)  // skip order channel
		}

		if (this.split) {
			this.writeLong(this.splitCount)
			this.writeLong(this.splitIndex)
			this.writeShort(this.splitID)
		}

		// Append content to the encoding
		this.buffer = Buffer.concat([this.buffer, this.content.buffer])
	}

	readACK() {
		let recordCount = this.readShort()
		this.packets = []
		for (let i = 0; i < recordCount; i++) {
			let recordType = this.readByte()
			switch (recordType) {
				case RecordTypes.Range:
					let start = this.readLTriad()
					let end = this.readLTriad()

					// Bruh... lazy to make new class just for ACKs and NACKs
					for (let pack = start; pack <= end; pack++) {
						this.packets.push(pack)

						if (this.packets.length > MaxAcknowledgementPackets) {
							console.log(this.packets.length)
							throw new Error('maximum amount of packets in acknowledgement exceeded')
						}
					}

				case RecordTypes.Single:
					let packet = this.readLTriad()
					this.packets.push(packet)

					if (this.packets.length > MaxAcknowledgementPackets) {
						throw new Error('maximum amount of packets in acknowledgement exceeded')
					}
			}
		}
	}

	// Returns if the packet is reliable
	reliable() {
		if (this.reliability === PacketReliability.Reliable ||
			this.reliability === PacketReliability.ReliableOrdered ||
			this.reliability === PacketReliability.ReliableSequenced) {
			return true
		}
		return false
	}

	// Returns if the packet is sequenced or ordered 
	sequencedOrOrdered() {
		if (this.reliability === PacketReliability.UnreliableSequenced ||
			this.reliability === PacketReliability.ReliableOrdered ||
			this.reliability === PacketReliability.ReliableSequenced) {
			return true
		}
		return false
	}

	// Returns if the packet is sequenced  
	sequenced() {
		if (this.reliability === PacketReliability.UnreliableSequenced ||
			this.reliability === PacketReliability.ReliableSequenced) {
			return true
		}
		return false
	}

	// Writes a ipv4 (at the moment) address into buffer
	writeAddress(address) {
		this.writeByte(4)
		if (!typeof address.address === "string") {
			throw new Error("The address must be a string")
		}
		address.address.split(".", 4).forEach(b => this.writeByte((Number(b)) & 0xff))
		this.writeShort(address.port)
	}

	// readAddress reads a RakNet address passed into the buffer 
	readAddress() {
		let ver = this.readByte()
		if (ver == 4) {
			// Read 4 bytes 
			let ipBytes = this.buffer.slice(this.offset, this.offset+=4)
            let addr = `${(-ipBytes[0]-1)&0xff}.${(-ipBytes[1]-1)&0xff}.${(-ipBytes[2]-1)&0xff}.${(-ipBytes[3]-1)&0xff} `
            let port = this.readShort()
            return {ip: addr, port: port, version: ver}
		} else {
			this.offset += 2 // Skip 2 bytes
			let port = this.readShort()
			this.offset += 4 // Skip 4 bytes
			let addr = this.buffer.slice(this.offset, this.offset += 16)
			this.offset += 4  // Skip 4 bytes
			return {address: addr, port: port, version: ver}
		}
	}

	writeACK(ack) {
		let packets = ack.packets
		if (packets.length == 0) {
			return this.writeShort(0)
		}
		let buffer = new Binary()
		packets = packets.sort((x, y) => {
			return x - y
		})
		let firstPacketInRange = 0
		let lastPacketInRange
		let recordCount = 0
	}
}

// Class used to semplify the reading of offline messages
const MAGIC = '\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
class OfflinePacket extends Packet {

	readMagic() {
		// can't slice manually with [start:end] :(
		this.magic = this.buffer.slice(this.offset, this.offset+=16) // slice the buffer to read magic bytes
	}

	writeMagic() {
		this.buffer = Buffer.concat([this.buffer, Buffer.from(MAGIC, 'binary')])
	}

	isValid() {
        return Buffer.from(this.magic).equals(Buffer.from(MAGIC, 'binary'))
    }
}

// Client -> server
// Custom classes to decode and encode packet data
class UnconnectedPing extends OfflinePacket {

	read() {
		this.readByte() // don't read packet ID
		this.sendTimeStamp = this.readLong()
		this.magic = this.readMagic() 
		this.clientGUID = this.readLong()
	}
}

// Server -> client
class UnconnectedPong extends OfflinePacket {

	// At the moment i don't care if magic is not a constant but we get it from another decoded packet
	constructor(sendTimeStamp, serverGUID) {
		super()
		this.sendTimeStamp = sendTimeStamp
		this.serverGUID = serverGUID
	}

	write() {
		this.writeByte(OfflinePackets.UnconnectedPong)
		this.writeLong(this.sendTimeStamp)
		this.writeLong(this.serverGUID) 
		this.writeMagic()
		this.writeString(NAME)
	}
}

// Client -> server
class OpenConnectionRequest1 extends OfflinePacket {

	read() {
		this.readByte() // skip header / id
		this.mtuSize = (Buffer.byteLength(this.buffer) + 1) + 28
		this.readMagic()
		this.protocol = this.readByte()
	}
}

// Server -> client
class OpenConnectionReply1 extends OfflinePacket {

	constructor(serverGUID, mtuSize) {
		super()
		this.serverGUID = serverGUID
		this.mtuSize = mtuSize
	}

	write() {
		this.writeByte(OfflinePackets.OpenConnectionReply1)
		this.writeMagic()
		this.writeLong(this.serverGUID)
		this.writeByte(0)  // secure ? 
		this.writeShort(this.mtuSize)
	}
}

// Client -> server
class OpenConnectionRequest2 extends OfflinePacket {

	read() {
		this.readByte()  // skip header
		this.readMagic()
		this.serverAddress = this.readAddress()
		this.mtuSize = this.readShort()
		this.clientGUID = this.readLong()
	}
}

// Server -> client
class OpenConnectionReply2 extends OfflinePacket {

	constructor(serverGUID, clientAddress, mtuSize) {
		super()
		this.serverGUID = serverGUID
		this.clientAddress = clientAddress
		this.mtuSize = mtuSize
	}

	write() {
 		this.writeByte(OfflinePackets.OpenConnectionReply2)
 		this.writeMagic()
 		this.writeLong(this.serverGUID)
 		this.writeAddress(this.clientAddress)
 		this.writeShort(this.mtuSize)
 		this.writeByte(0)  // secure ? 
	}
}

// This class handles a player connection after offline packets
const RESEND_REQUEST_THRESHOLD = 10
const ConnectedPackets = {
	ConnectionRequest: 0x09,
	ConnectionRequestAccepted: 0x10,
	NewIncomingConnection: 0x13,
	ConnectedPing: 0x00,
	ConnectedPong: 0x03,
	DisconnectNotification: 0x15
}
const PacketAdditionalSize = 1 + 3 + 1 + 2 + 3 + 3 + 1
const SplitAdditionalSize = 4 + 2 + 4
class Connection {

	constructor(client, address, mtuSize, id) {
		if (mtuSize < 500 || mtuSize > 1500) {
			mtuSize = 1942
		}

		this.client = client
		this.address = address  // remoteInfo

		this.connected = false

		this.lastSequenceNumber = 0
		this.nackQueue = []  // array that includes sequenceNumbers
		this.ackQueue = []  // array that includes sequenceNumbers

		this.sendSequenceNumber = 0
		this.sendOrderIndex = 0
		this.sendMessageIndex = 0
		this.sendSplitID = 0

		this.id = id
		this.mtuSize = mtuSize

		this.latency = 0

		this.splits = new Map()

		this.packetQueue = new PacketQueue()
		this.lastPacketTime = 0

		this.recoveryQueue = new PacketQueue()

		this.datagramRecvQueue = new PacketQueue()
		this.datagramsReceived = []
		this.missingDatagramTimes = 0

		this.startTicking()
	}

	startTicking() {
        let ticker = setInterval(() => {
        	if (this.lastPacketTime > 7) {
        		// console.log('Timeout')
        		// this.close()  TODO
        	}
        	this.checkResend()
        }, 1 / 100 * 1000)

        let pingTicker = setInterval(() => {
			// this.sendPing()
        }, 60 * 4)
	}

	receive(message) {
		let packet = new Packet(message)
		let headerFlags = packet.readByte()
		// Check if the packet is an offline message and don't andle them if it is
		if (headerFlags&BitFlags.Valid == 0) {
			return
		}

		if (headerFlags&BitFlags.Ack) {
			return this.handleACK(packet)
		} else if (headerFlags&BitFlags.Nack) {
			//return this.handleNACK(packet)
		} else {
			return this.receiveDatagram(packet)
		}
	}

	receiveDatagram(datagram) {
		let sequenceNumber = datagram.buffer.readUIntLE((datagram.offset += 3) - 3, 3)

		if (this.datagramRecvQueue.put(sequenceNumber, true)) {
			// FUCK
			// throw new Error("Error handing datagram: datagram already received")
		}
			
		this.datagramsReceived.push(sequenceNumber)
		if (this.datagramRecvQueue.takeOut().length == 0) {
			this.missingDatagramTimes++
			if (this.missingDatagramTimes >= RESEND_REQUEST_THRESHOLD) {
				// TODO: send NACK for every missing packet
			}
		} else {
			this.missingDatagramTimes = 0
		}

		// Check if it's an invalid packet
		if (datagram.buffer.length > 0) {
			// Should i set it just when diff is right (equals to 1)
			this.lastSequenceNumber = sequenceNumber  // update last sequence number

			// Decode packet data
			datagram.readDatagram()

			// If the packet has split because of mtu size, we should save packet parts
			if (datagram.split) {
				this.handleSplitPacket(datagram)
			} else {
				this.receivePacket(datagram)
			}
		}
	}

	// Handles a splitted datagram packet
	handleSplitPacket(datagram) {
		let m = this.splits.has(datagram.splitID)
		if (m) {
			m = this.splits.get(datagram.splitID)
			m.set(datagram.splitIndex, datagram)
			this.splits.set(datagram.splitID, m)
		} else {
			m = new Map([[datagram.splitIndex, datagram]])
            this.splits.set(datagram.splitID, m)
		}

		// Check if we have all splits
		if (this.splits.get(datagram.splitID).size == datagram.splitCount) {
			let packet = new Packet()
			for (let [splitIndex, fragment] of this.splits.get(datagram.splitID)) {
				console.log(fragment)
				packet.buffer = Buffer.concat([packet.buffer, fragment.buffer])
			}
			return this.receivePacket(packet)
		}
	}

	receivePacket(packet) {
		if (packet.reliability !== PacketReliability.ReliableOrdered) {
			// Skip queue and handle immediately if it isn't a reliable ordered
			return this.handlePacket(packet.content)
		}

		// If this returns true, there was an error
		if (this.packetQueue.put(packet.orderIndex, packet.content)) {
			if (packet.orderIndex == 0 && !this.packetQueue.zeroRcv) {  
				return this.handlePacket(packet.content)
			}
		}

		// Works fine :P
		for (let packetContent of this.packetQueue.takeOut()) {
			this.handlePacket(packetContent)
		}
	}

	handlePacket(packet) {
		let id = packet.readByte()

		// Used for connection time out
		this.lastPacketTime = Date.now()

		switch(id) {
			case ConnectedPackets.ConnectionRequest:
				if (this.connected) {
					return
				}
				return this.handleConnectionRequest(packet)
			case ConnectedPackets.ConnectionRequestAccepted:
				if (this.connected) {
					return
				}
				return this.handleConnectionRequestAccepted(packet)
			case ConnectedPackets.NewIncomingConnection:
				return this.handleNewIncomingConnection(packet)
			case ConnectedPackets.ConnectedPing:
				return this.handleConnectedPing(packet)
			case ConnectedPackets.ConnectedPong:
				return this.handleConnectedPong(packet)
			case ConnectedPackets.DisconnectNotification:
				return this.handleDisconnectNotification(packet)
			case 0x04:
				return
			default:
				// TODO
				console.log("We got into a todo :P")
				// console.log(packet)				
		}
	}

	handleConnectionRequest(packet) {
		let decodedPk = new ConnectionRequest(packet.buffer)
		decodedPk.read()
		let encodedPk = new ConnectionRequestAccepted(this.address, decodedPk.requestTimeStamp, Math.floor(Date.now() / 1000))
		encodedPk.write()
		this.write(encodedPk)
	}

	handleNewIncomingConnection(packet) {
		this.connected = true
		console.log('Connected')
	}

	handleDisconnectNotification(packet) {
		console.log('DisconnectNotification')
		this.connected = false
		return  // TODO
	}

	handleConnectedPing(packet) {
		let decodedPk = new ConnectedPing(packet.buffer)
		decodedPk.read()
		let encodedPk = new ConnectedPong(decodedPk.clientTimeStamp, Math.floor(Date.now() / 1000))
		encodedPk.write()
		this.write(encodedPk)
	}

	handleACK(packet)  {
		packet.readACK()

		// Mhh.. nothing to do really
		for (let sequenceNumber of packet.packets) {
			let p = this.recoveryQueue.take(sequenceNumber)
			p.content = new Binary()
		}
	}

	checkResend() {

	}

	sendPing() {
		// let encodedPk = new ConnectedPing(Math.floor(Date.now() / 1000))
		// encodedPk.write()
		// this.write(encodedPk)
	}

	// Seems to be working, need to test with bigger packets
	split(packet) {
		let maxSize = (this.mtuSize - PacketAdditionalSize) - 28
		let contentLength = packet.buffer.length  // check this
		if (contentLength > maxSize) {
			maxSize -= SplitAdditionalSize
		}
		let fragmentCount = Math.ceil(contentLength / this.mtuSize)
		if (contentLength%maxSize !== 0) {
			fragmentCount++
		}
		let fragments = new Map()
		let offset = 0
		for (let i = 0; i < fragmentCount; i++) {
			let buf = packet.buffer.slice(offset, offset+=maxSize)
			if (buf.length == 0) {
				continue  // skip if it is 0 lenght or maybe break it directly?
			}
			fragments.set(i, buf) 
		}
		return fragments
	}

	write(packet) {
		// if split works, this works as well
		let fragments = this.split(packet)
		for (let[splitIndex, content] of fragments) {
			let sequenceNumber = this.sendSequenceNumber
			this.sendSequenceNumber++
			let messageIndex = this.sendMessageIndex 
			this.sendMessageIndex++

			let binary = new Binary()
			binary.writeByte(BitFlags.Valid)
			binary.writeLTriad(sequenceNumber)

			let packet = new Packet(binary.buffer)
			if (typeof packet.content !== "undefined") {
				packet.content = new Binary(Buffer.concat([packet.content.buffer, content]))
			} else {
				packet.content = new Binary(content)
			}

			packet.orderIndex = this.sendOrderIndex
			packet.messageIndex = messageIndex

			if (fragments.length > 1) {
				packet.split = true
				packet.splitCount = fragments.size
				packet.splitIndex = splitIndex
				packet.splitID = splitID
			} else {
				packet.split = false
			}

			packet.writeDatagram()
			socket.send(packet.buffer, 0, packet.buffer.length, this.address.port, this.address.address)

			// Add recovery for the packet
			this.recoveryQueue.put(sequenceNumber, packet)
		}
	}
}


// Server -> client
class ConnectionRequest extends Packet {

	read() {
		this.readByte() // skip PID
		this.clientGUID = this.readLong()
		this.requestTimeStamp = this.readLong()
		this.secure = this.readByte()
	}
}

// Client -> server
class ConnectionRequestAccepted extends Packet {

	constructor(clientAddress, requestTimeStamp, acceptedTimestamp) {
		super()
		this.clientAddress = clientAddress
		this.requestTimeStamp = requestTimeStamp
		this.acceptedTimestamp = acceptedTimestamp
	}

	write() {
		this.writeByte(ConnectedPackets.ConnectionRequestAccepted)
		this.writeAddress(this.clientAddress)
		this.writeShort(0)  // unknown
		// For some reasons it works with just 10 addresses, source JRakNet
		for (let i = 0; i < 20; i++) {
			this.writeAddress({address: '0.0.0.0', port: 0, version: 4})
		}
		this.writeLong(this.requestTimeStamp)
		this.writeLong(this.acceptedTimestamp)
	}
}

// Client -> server
// Server -> client
class ConnectedPing extends Packet {

	/* constructor(clientTimeStamp) {
		super()
		this.clientTimeStamp = clientTimeStamp
	}

	write() {
		this.writeByte(ConnectedPackets.ConnectedPing)
		this.writeLong(this.clientTimeStamp)
	} */

	read() {
		console.log(this.buffer)
		this.readByte() // ignore PID
		this.clientTimeStamp = this.readLong()
	}
}

// Server -> client
// Client -> server
class ConnectedPong extends Packet {

	constructor(clientTimeStamp, serverTimeStamp) {
		super()
		this.clientTimeStamp = clientTimeStamp
		this.serverTimeStamp = serverTimeStamp
	}

	/* read() {

	} */

	write() {
		this.writeByte(ConnectedPackets.ConnectedPong)
		this.writeLong(this.clientTimeStamp)
		this.writeLong(this.serverTimeStamp)
	}
}

// This class holds packet queues
const DelayRecordCount = 40
class PacketQueue extends Map {

	constructor() {
		super()
		this.queue = new Map()
		this.timestamps = new Map()
		this.lowestIndex = 0
		this.highestIndex = 0
		this.lastClean = Date.now()

		this.zeroRcv = false

		this.ptr = 0
		this.delays = new Map()
	}

	takeOut() {
		let values = []
		let index = this.lowestIndex
		for (index; index < this.highestIndex; index++) {
			let value = this.queue.get(index)
			this.queue.delete(index)
			this.timestamps.delete(index)
			if (!value) {
				continue
			}
			values.push(value)
		}
		this.lowestIndex = index
		return values
	}

	put(index, value) {
		if (index == 0) {
			this.zeroRcv = true
		}
		if (index < this.lowestIndex) {
			return true
			// throw new Error("cannot set value at index %s: already taken out", index)
		}
		if (this.queue.has(index)) {
			return true
			// Packets can be sent multiple times... not a critial error
			// throw new Error("cannot set value at index %s: already has a value", index)
		}
		if (index+1 > this.highestIndex) {
			this.highestIndex = index + 1
		}
		this.queue.set(index, value)
		this.timestamps.set(index, Date.now())
	}

	take(index) {
		let val = this.queue.get(index)
		this.queue.delete(index)
		this.delays.set(this.ptr, Date.now() - this.timestamps.get(index))
		this.ptr++
		if (this.ptr == DelayRecordCount) {
			this.ptr = 0
		}
		this.timestamps.delete(index)
		return val
	}
}
