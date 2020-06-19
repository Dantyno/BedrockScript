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
	Nack: 0x20
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
socket.bind(PORT, HOST);

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
	// int 8 => 1 byte
	// int16 => 2 bytes 
	// int32 => 4 bytes
	// int64 => 8 bytes

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
}

// Packet object containing the offset of the buffer and other stuff we may need
class Packet extends Binary {

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
        return Buffer.from(this.magic).equals(Buffer.from(MAGIC, 'binary'));
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
class Connection {

	constructor(client, address, mtuSize, id) {
		if (mtuSize < 500 || mtuSize > 1500) {
			mtuSize = 1942
		}

		this.client = client
		this.address = address  // remoteInfo

		this.sendSequenceNumber = 0
		this.sendOrderIndex = 0
		this.sendMessageIndex = 0
		this.sendSplitID = 0

		this.id = id
		this.mtuSize = mtuSize

		this.latency = 0

		this.splits = new Map()

		this.datagramRecvQueue = new OrderedQueue()

		this.datagramsReceived = []

		this.missingDatagramTimes = 0

		this.packetQueue = new OrderedQueue()
		this.lastPacketTime = 0

		this.recoveryQueue = new OrderedQueue()
	}

	receive(message) {
		let packet = new Packet(message)
		let headerFlags = packet.readByte()
		// Check if the packet is an offline message and don't andle them if it is
		if (headerFlags&BitFlags.Valid == 0) {
			return
		}

		if (headerFlags&BitFlags.Ack !== 0) {
			// TODO return this.handleACK(message)
		} else if (headerFlags&BitFlags.Nack !== 0) {
			// TODO return this.handleNACK(message)
		} else {
			return this.receiveDatagram(packet)
		}
	}

	receiveDatagram(datagram) {
		let sequenceNumber = datagram.buffer.readUIntLE((datagram.offset += 3) - 3, 3)
		this.datagramRecvQueue.put(sequenceNumber, true)
		this.datagramsReceived.push(sequenceNumber)
		let out = this.datagramRecvQueue.takeOut()
		if (out.length == 0) {
			this.missingDatagramTimes++
			if (this.missingDatagramTimes >= RESEND_REQUEST_THRESHOLD) {

			}
		}
	}

	sendNACK(packets...) {
		let ack = {packets: packets}
		let buffer = new Packet()
		buffer.writeACK()
	}
}

// This class holds packet queues
class OrderedQueue {

	constructor() {
		this.queue = new Map()
		this.timestamps = new Map()
		this.lowestIndex = 0
		this.highestIndex = 0
		this.lastClean = Date.now()

		this.zeroRecv = false

		this.ptr = 0
	}

	put(index, value) {
		if (index == 0) {
			this.zeroRecv = true
		}
		if (index < this.lowestIndex) {
			return new Error("cannot set value at index %s: already taken out", index)
		}
		if (this.queue.has(index)) {
			throw new Error("cannot set value at index %v: already has a value", index)
		}
		if (index+1 > this.queue.highestIndex) {
			this.highestIndex = index + 1
		}
		this.queue.set(index, value)
		this.timestamps.set(index, Date.now())
	}

	takeOut() {
		let values = []
		let index = 0
		for (index = this.lowestIndex; index < this.highestIndex; index++) {
			let value = this.queue.get(index)
			this.queue.remove(index)
			this.timestamps.remove(index)
			if (value == null) {
				continue
			}
			values.push(value)
		}
		this.lowestIndex = index
		return values
	}

	missing() {
		let indices = []
		for (let index = this.lowestIndex; index < this.highestIndex; index++) {
			if (this.queue.has(index)) {
				indices.push(index)
				this.queue.set(index, null)
			}
		}
		return indices
	}
}
