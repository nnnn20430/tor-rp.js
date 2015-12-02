#!/usr/bin/env node
// tor-rp.js, random copied nBot functions to make a tor reverse proxy
// Copyright (C) 2015  nnnn20430 (nnnn20430@mindcraft.si.eu.org)
//
// tor-rp.js is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tor-rp.js is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

var net = require('net');
var fs = require('fs');

var connections = [];

//settings management
var SettingsConstructor = {
	connection: function (modified) {
		//force 'new' object keyword
		if(!(this instanceof SettingsConstructor.connection)) {
			return new SettingsConstructor.connection(modified);
		}
		var attrname;
		this.bindPort = 7800;
		this.tor = {
			host: "127.0.0.1",
			port: 9050
		};
		this.remote = {
			host: "xxxxxxxxxxxxxxxx.onion",
			port: 80
		};
		for (attrname in modified) {this[attrname]=modified[attrname];}
	}
};

function settingsLoad(file, callback) {
	file = file||"tor-rp-settings.json";
	fs.access(file, fs.F_OK, function (err) {
		if (!err) {
			fs.readFile(file, {"encoding": "utf8"}, function (err, data) {
				if (err) throw err;
				if (callback !== undefined) {
					callback(JSON.parse(data));
				}
			});
		} else if (err.code == "ENOENT"){
			var newSettings = [new SettingsConstructor.connection()];
			fs.writeFile(file, JSON.stringify(newSettings, null, '\t'), function (err) {if (err) throw err; callback(newSettings);});
		}
	});
}

Object.defineProperty(String.prototype, "toHex", { 
	value: function(a) {
		return new Buffer(this.toString(), 'utf8').toString('hex');
	},
	configurable: true,
	writable: true,
	enumerable: false
});

Object.defineProperty(String.prototype, "fromHex", { 
	value: function(a) {
		return new Buffer(this.toString(), 'hex').toString('utf8');
	},
	configurable: true,
	writable: true,
	enumerable: false
});

//https://gist.github.com/Mottie/7018157
function expandIPv6Address(address) {
	var fullAddress = "";
	var expandedAddress = "";
	var validGroupCount = 8;
	var validGroupSize = 4;
	var i;

	var ipv4 = "";
	var extractIpv4 = /([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/;
	var validateIpv4 = /((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})/;

	// look for embedded ipv4
	if(validateIpv4.test(address))
	{
		groups = address.match(extractIpv4);
		for(i=1; i<groups.length; i++)
		{
			ipv4 += ("00" + (parseInt(groups[i], 10).toString(16)) ).slice(-2) + ( i==2 ? ":" : "" );
		}
		address = address.replace(extractIpv4, ipv4);
	}

	if(address.indexOf("::") == -1) // All eight groups are present.
		fullAddress = address;
	else // Consecutive groups of zeroes have been collapsed with "::".
	{
		var sides = address.split("::");
		var groupsPresent = 0;
		for(i=0; i<sides.length; i++)
		{
			groupsPresent += sides[i].split(":").length;
		}
		fullAddress += sides[0] + ":";
		for(i=0; i<validGroupCount-groupsPresent; i++)
		{
			fullAddress += "0000:";
		}
		fullAddress += sides[1];
	}
	var groups = fullAddress.split(":");
	for(i=0; i<validGroupCount; i++)
	{
		while(groups[i].length < validGroupSize)
		{
			groups[i] = "0" + groups[i];
		}
		expandedAddress += (i!=validGroupCount-1) ? groups[i] + ":" : groups[i];
	}
	return expandedAddress;
}

function randomStringGen(len, charSet) {
	charSet = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var randomString = '';
	for (var i = 0; i < len; i++) {
		var randomPoz = Math.floor(Math.random() * charSet.length);
		randomString += charSet.substring(randomPoz,randomPoz+1);
	}
	return randomString;
}

function torReverseProxyServerInit (settings) {
	var server = net.createServer(function(c) { //'connection' listener
		var clientAddr = c.remoteAddress, clientPort = c.remotePort;
		var tempBuffer = new Buffer(0);
		var tor, torConnected = false;
		var id = randomStringGen(8);
		c.on('error', function (e) {
			c.end(); c.destroy();
			tor.end(); tor.destroy();
			debugLog('client "'+clientAddr+':'+clientPort+'" connection error');
			});
		c.on('timeout', function (e) {
			c.end(); c.destroy();
			tor.end(); tor.destroy();
			debugLog('client "'+clientAddr+':'+clientPort+'" connection timed out');
		});
		c.on('end', function() {
			c.end();
			tor.end(); tor.destroy();
		});
		c.on('close', function() {
			tor.end(); tor.destroy();
			debugLog('client "'+clientAddr+':'+clientPort+'" socket closed');
		});
		function debugLog(data) {
			console.log('('+id+') '+data);
		}
		function tempBufferListener () {
			c.once('data', function (chunk) {
				c.setEncoding('hex');
				if (!torConnected) {
					tempBuffer = Buffer.concat([tempBuffer, new Buffer(chunk, 'hex')]);
					tempBufferListener();
				}
			});
		}
		tempBufferListener();
		function handleClient() {
			torConnected = true;
			tor.write(tempBuffer);
			debugLog('tor connection for client "'+clientAddr+':'+clientPort+'" opend!');
			c.setEncoding('hex');
			tor.setEncoding('hex');
			c.on('data', function (chunk) {
				tor.write(new Buffer(chunk, 'hex'));
			});
			tor.on('data', function (chunk) {
				c.write(new Buffer(chunk, 'hex'));
			});
		}
		function initSocks(c, host, port, user, pass, callback) {
			var ipAddr;
			var octet;
			var ATYP = net.isIP(host);
			var DST_ADDR = '';
			var DST_PORT = ('00'+numToHexByte(+port)).slice(-4);
			switch (ATYP) {
				case 0:
					ATYP = '03';
					DST_ADDR += numToHexByte(+host.length);
					DST_ADDR += host.toHex();
					break;
				case 4:
					ATYP = '01';
					ipAddr = host.split('.');
					for (octet in ipAddr) {
						DST_ADDR += numToHexByte(+ipAddr[octet]);
					}
					break;
				case 6:
					ATYP = '04';
					ipAddr = expandIPv6Address(host).split(':');
					for (octet in ipAddr) {
						DST_ADDR += ipAddr[octet];
					}
					break;
			}
			function numToHexByte(num) {
				var hex = num.toString(16);
				if ((hex.length/2)%1 !== 0) {
					hex = '0'+hex;
				}
				return hex;
			}
			function requestConnect() {
				//socks5(05), connect(01), reserved(00)
				c.write(new Buffer('050100'+ATYP+DST_ADDR+DST_PORT, 'hex'));
				c.once('data', function (data) {
					//00 == succeeded
					if (data.substr(2*1, 2) == '00') {
						callback();
					} else {
						debugLog('Error: Proxy traversal failed');
					}
				});
			}
			function sendUnamePasswdAuth() {
				var ULEN = numToHexByte(user.length);
				var UNAME = user.toHex();
				var PLEN = numToHexByte(pass.length);
				var PASSWD = pass.toHex();
				c.write(new Buffer('01'+ULEN+UNAME+PLEN+PASSWD, 'hex'));
				c.once('data', function (data) {
					//00 == succeeded
					if (data.substr(2*1, 2) == '00') {
						requestConnect();
					} else {
						debugLog('Error: Proxy auth failed');
					}
				});
			}
			(function () {
				var NMETHODS = 1;
				var METHODS = '00';
				if (user && pass) {
					NMETHODS += 1;
					METHODS += '02';
				}
				c.setEncoding('hex');
				c.write(new Buffer('05'+numToHexByte(NMETHODS)+METHODS, 'hex'));
				c.once('data', function (data) {
					if (data.substr(2*0, 2) == '05') {
						if (data.substr(2*1, 2) == '00') {
							requestConnect();
						} else if (data.substr(2*1, 2) == '02') {
							sendUnamePasswdAuth();
						} else if (data.substr(2*1, 2) == 'ff') {
							debugLog('Error: Proxy rejected all known methods');
						}
					}
				});
			})();
		}
		function connectTor() {
			tor = net.connect(settings.tor,
				function() { //'connect' listener
					initSocks(tor, settings.remote.host,
						settings.remote.port,
						null,
						null, handleClient);
			});
			tor.once('error', function (e) {
				tor.end(); tor.destroy();
				c.end(); c.destroy();
				debugLog('tor connection for client "'+clientAddr+':'+clientPort+'" error: ('+e+').');
			});
			tor.once('timeout', function (e) {
				tor.end(); tor.destroy();
				c.end(); c.destroy();
				debugLog('tor connection for client "'+clientAddr+':'+clientPort+'" timeout');
			});
			tor.on('end', function() {
				tor.end();
				c.end(); c.destroy();
			});
			tor.once('close', function () {
				c.end(); c.destroy();
				debugLog('tor connection for client "'+clientAddr+':'+clientPort+'" closed.');
			});
		}
		debugLog('client "'+clientAddr+':'+clientPort+'" connected!');
		connectTor();
	});
	server.listen(settings.bindPort, function() { //'listening' listener
		console.log('ready to reverse proxy "'+settings.remote.host+':'+settings.remote.port+'" on port '+settings.bindPort+'');
	});
}

settingsLoad(null, function (data) {
	connections = data;
	for (var connection in connections) {
		torReverseProxyServerInit(connections[connection]);
	}
});
