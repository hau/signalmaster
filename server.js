/*global console*/
var yetify = require('yetify'),
    config = require('getconfig'),
    uuid = require('node-uuid'),
    crypto = require('crypto'),
    io = require('socket.io').listen(config.server.port);

function describeRoom(name) {
    var clients = io.sockets.clients(name);
    var result = {
        clients: {}
    };
    clients.forEach(function (client) {
        result.clients[client.id] = client.resources;
    });
    return result;
}

function safeCb(cb) {
    if (typeof cb === 'function') {
        return cb;
    } else {
        return function () {};
    }
}

io.sockets.on('connection', function (client) {
    client.resources = {
        screen: false,
        video: true,
        audio: false
    };

    // pass a message to another id
    client.on('message', function (details) {
        var otherClient = io.sockets.sockets[details.to];
        if (!otherClient) return;
        details.from = client.id;
        otherClient.emit('message', details);
    });

    client.on('shareScreen', function () {
        client.resources.screen = true;
    });

    client.on('unshareScreen', function (type) {
        client.resources.screen = false;
        if (client.room) removeFeed('screen');
    });

    client.on('join', join);

    function removeFeed(type) {
        io.sockets.in(client.room).emit('remove', {
            id: client.id,
            type: type
        });
    }

    function join(name, cb) {
        // sanity check
        if (typeof name !== 'string') return;

				var secret = require("./secret");
				var key = secret.key; 
				key = crypto.createHash('sha256').update(key, 'ascii').digest();
				var iv = secret.iv;

				// name is encrypted string of "#{room access time}"
				var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
				var decryptedString = decipher.update(name, 'base64', 'utf8');
				decryptedString += decipher.final('utf8');
				// turn the decrypted string into a date time
				var accessToken = JSON.parse(decryptedString);

				console.log("decrypted time=" + accessToken.timestamp);
				var now = new Date();
				console.log("now=" + now.valueOf());
				console.log("time difference=" + (now.valueOf() - accessToken.timestamp));
				// if joining room much later than request for access token (5s)
				if ((now.valueOf() - accessToken.timestamp) > 5000) return;

				console.log("Joining room: " + accessToken.room);
        // leave any existing rooms
        if (client.room) removeFeed();
        safeCb(cb)(null, describeRoom(accessToken.room));
        client.join(accessToken.room);
        client.room = accessToken.room;
/*
				console.log("Joining room: " + name);
        // leave any existing rooms
        if (client.room) removeFeed();
        safeCb(cb)(null, describeRoom(name));
        client.join(name);
        client.room = name;
*/
    }

    // we don't want to pass "leave" directly because the
    // event type string of "socket end" gets passed too.
    client.on('disconnect', function () {
        removeFeed();
    });
    client.on('leave', removeFeed);

    client.on('create', function (name, cb) {
        if (arguments.length == 2) {
            cb = (typeof cb == 'function') ? cb : function () {};
            name = name || uuid();
        } else {
            cb = name;
            name = uuid();
        }
        // check if exists
        if (io.sockets.clients(name).length) {
            safeCb(cb)('taken');
        } else {
            join(name);
            safeCb(cb)(null, name);
        }
    });

    // tell client about stun and turn servers and generate nonces
    if (config.stunservers) {
        client.emit('stunservers', config.stunservers);
    }
    if (config.turnservers) {
        // create shared secret nonces for TURN authentication
        // the process is described in draft-uberti-behave-turn-rest
        var credentials = [];
        config.turnservers.forEach(function (server) {
            var hmac = crypto.createHmac('sha1', server.secret);
            // default to 86400 seconds timeout unless specified
            var username = new Date().getTime() + (server.expiry || 86400) + "";
            hmac.update(username);
            credentials.push({
                username: username,
                credential: hmac.digest('base64'),
                url: server.url
            });
        });
        client.emit('turnservers', credentials);
    }
});

if (config.uid) process.setuid(config.uid);
console.log(yetify.logo() + ' -- signal master is running at: http://localhost:' + config.server.port);
