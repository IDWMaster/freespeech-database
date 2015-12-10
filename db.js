var mongo = require('mongodb');
var net = require('net');
var child_process = require('child_process');
var fs = require('fs');
var NodeRSA = require('node-rsa');
var db;
var dbReadyCallback;

var DistDocument = function() {
    var pubkey; //The public key for the document
    var contents; //A binary BLOB containing the contents of the document (raw object)
    
    return {
        
    };
};

/**
 * Distributed key-value database
 * @type type
 */
var DistDB = {
    /**
     * Adds a document to DistDB
     * @param {DistDocument} document The document to add
     * @returns {undefined}
     */
  add:function(document) {
      
  }  
};



/**
 * Information about "first hop servers" -- nodes that have been identified as good candidates for initial session establishment.
 */
var FirstHopServers = {
    add: function (ip, portno, thumbprint) {
        db.collection('firsthops').insertOne({ip: ip, portno: portno, thumbprint: thumbprint});
    },
    remove: function (thumbprint) {
        db.collection('firsthops').deleteMany({thumbprint: thumbprint}, function (err, delcount) {});
    },
    enumerate: function (callback) {
        db.collection('firsthops').find().each(function (err, doc) {
            if (doc) {
                callback(doc);
            } else {
                callback(null);
            }
        });
    }
};


//Local key database
var EncryptionKeys = {
    enumPrivateKeys: function (callback) {
        db.collection('keys').find({hasPrivate: true}).each(function (err, doc) {
            if (err) {
                callback(null);
                return false;
            }
            if (doc) {
                var key = new NodeRSA();
                ;
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            } else {
                return callback(null);
            }
        });
    },
    getDefaultKey: function (callback) {
        db.collection('keys').find({hasPrivate: true, isDefault: true}).each(function (err, doc) {
            if (!doc) {
                callback(null);
                return false;
            } else {
                var key = new NodeRSA();
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            }
        });
    },
    findKey: function (thumbprint, callback) {
        db.collection('keys').find({thumbprint: thumbprint}).each(function (err, doc) {
            if (doc) {
                var key = new NodeRSA();
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            }
            callback(null);
            return false;
        });
    },
    add: function (key, callback, isDefault) {
        var binkey = key.exportKey('pkcs1-der');
        var doc = {
            hasPrivate: !key.isPublic(true),
            key: binkey,
            thumbprint: key.thumbprint(),
            isDefault: (isDefault == true)
        };
        db.collection('keys').insertOne(doc, function (err, r) {
            if (err) {
                callback(false);
            } else {
                callback(true);
            }
        });
    }
};






var exitHandlers = new Array();
function exitHandler(options, err) {

    for (var i = 0; i < exitHandlers.length; i++) {
        try {
            exitHandlers[i]();
        } catch (er) {

        }
    }


    if (options.exit) {
        process.exit();
    }

};


var server = net.createServer(function (client) {});
fs.mkdir('db', function () {
    server.listen(0, '::');
    server.on('listening', function () {
        var portno = server.address().port;
        server.close();
        server.once('close', function () {
            var proc = child_process.spawn('mongod', ['--port', portno, '--dbpath', 'db', '--bind_ip', '127.0.0.1', '--logpath', 'db/log.txt']);
            proc.on('error', function (er) {
                throw er;
            });
            exitHandlers.push(function () {
                proc.kill();
            });
            mongo.MongoClient.connect('mongodb://127.0.0.1:' + portno + '/FreeSpeech', function (err, mdb) {
                    if (err != null) {
                        console.log('Error establishing database connection.');
                        throw err;
                    }
                    db = mdb;
                    dbReadyCallback();
                });
        });
    });
    });
    module.exports = {
        EncryptionKeys:EncryptionKeys,
        FirstHopServers:FirstHopServers,
        onDbReady:function(callback){
            if(db) {
                callback();
            }else {
                dbReadyCallback = callback;
            }
        }
    };