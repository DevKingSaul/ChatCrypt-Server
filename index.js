const crypto = require('crypto');
const fs = require('fs');
const { WebSocketServer } = require('ws');

const wss = new WebSocketServer({ port: 8000 });

const keypair = crypto.createECDH('secp384r1');
keypair.generateKeys();

const publicKey = keypair.getPublicKey();

const rsaKey = crypto.createPrivateKey({
    key: fs.readFileSync("./private.pem"),
    type: "pkcs1"
})

const keypairSignature = crypto.sign(null, publicKey, rsaKey)
const handshakeMessage = publicKey.toString("hex")+"|"+keypairSignature.toString("base64");

const channels = {};

function encryptServerMessage(data, key) {
    const iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    const dataLength = data.length;
    const formedData =
      data + "\0".repeat((dataLength % 16 == 0 && 0) || 16 - (dataLength % 16));
    let encryptedData = cipher.update(formedData, "binary");
    encryptedData = Buffer.concat([
        encryptedData,
        cipher.final()
    ]);

    return (
      iv.toString("base64") +
      "|" +
      encryptedData.toString("base64")
      );
}

const ServerMessageRegex = /^[0-9a-zA-Z+\/]{22}==\|([0-9a-zA-Z+\/]{4})*(([0-9a-zA-Z+\/]{2}==)|([0-9a-zA-Z+\/]{3}=))?$/


function decryptServerMessage(data, key) {
    try {
      if (!ServerMessageRegex.test(data)) return {};  
      const parts = data.split("|");
      if (parts.length !== 2) return {};
      const iv = Buffer.from(parts[0], "base64");
      let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      decipher.setAutoPadding(false);
      let rawData = decipher.update(Buffer.from(parts[1], "base64"));
      rawData = Buffer.concat([
        rawData,
        decipher.final()
      ]);
      return JSON.parse(rawData.toString("binary").replace(/\0+$/, ""))
    } catch(e) {
      return {}
    }
}

function sendMemberList(ws, ChannelObject) {
    const memeberList = [];
    const wsMemberID = ws.MemberID;
    for (const MemberID in ChannelObject) {
        if (MemberID == wsMemberID) continue;
        memeberList.push(MemberID);
    }

    ws.send(encryptServerMessage(
        JSON.stringify({
            a: "l",
            p: memeberList
        }),
        ws.sharedSecret
    ))
}

function broadcastMemberList(ChannelObject) {
    for (const ws of Object.values(ChannelObject)) {
        sendMemberList(ws, ChannelObject);
    }
}

function addMemberToChannel(channelUUID, ws) {
    if (!channels[channelUUID]) {
        channels[channelUUID] = {};
    }

    const ChannelObject = channels[channelUUID];

    const MemberID = crypto.randomBytes(8).toString("hex");
    ChannelObject[MemberID] = ws;

    ws.channelUUID = channelUUID;
    ws.MemberID = MemberID;

    broadcastMemberList(ChannelObject);
}

function sendToClient(Sender, MemberID, data) {
    if (typeof MemberID !== "string") return;
    if (typeof data !== "string") return;
    const ChannelObject = channels[Sender.channelUUID];
    if (!ChannelObject) return;
    const Member = ChannelObject[MemberID];
    if (!Member) return;

    Member.send(encryptServerMessage(JSON.stringify({
        a: "c",
        c: Sender.MemberID,
        p: data
    }), Member.sharedSecret))
}

wss.on('connection', function connection(ws) {
    ws.on("message", (message) => {
        if (message.toString() == "ping") {
            ws.send("pong");
            return;
        }
        if (!ws.sharedSecret) {
            const publicKey = Buffer.from(message.toString(), "hex");
            if (publicKey.length != 97) return ws.close();
            ws.sharedSecret = keypair.computeSecret(publicKey).slice(8, 40);;
            ws.send(handshakeMessage);
        } else {
            const json = decryptServerMessage(message.toString(), ws.sharedSecret);

            console.log(json);

            switch(json.a) {
                case "j": {
                    if (ws.channelUUID) return;
                    if (typeof json.p !== "string") return;
                    addMemberToChannel(json.p, ws);
                    break;
                }

                case "w": {
                    if (!ws.channelUUID) return;
                    if (typeof json.p !== "object") return;

                    for (const [MemberID, data] of Object.entries(json.p)) {
                        sendToClient(ws, MemberID, data);
                    }
                    break;
                }

                case "c": {
                    if (!ws.channelUUID) return;
                    sendToClient(ws, json.c, json.p);
                }
            }
        }
    })

    ws.on("close", () => {
        ws.removeAllListeners();

        if (ws.channelUUID) {
            const ChannelObject = channels[ws.channelUUID];
            delete ChannelObject[ws.MemberID];

            if (Object.keys(ChannelObject).length === 0) {
                delete channels[ws.channelUUID];
            } else {
                broadcastMemberList(ChannelObject);
            }
        }
    })
});
