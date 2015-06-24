var kbpgp = require('kbpgp');

var renderStatus = function(i, s) {
    console.log(s);
};

var F = kbpgp.const.openpgp;
var KeyManager = kbpgp.KeyManager;
var keys = {
    key_pair: {
        fingerprint: null,
        key_manager: null,
        signed_public_key: null,
        private_key: null
    }
};

var opts = {
    userid: "Keybase Login Extension",
    primary: {
        nbits:     384,
        ecc:       true,
        flags:     F.certify_keys | F.sign_data | F.auth | F.encrypt_comm | F.encrypt_storage,
        expire_in: 60 * 15
    },
    subkeys: [{
        nbits:     384,
        flags:     F.sign_data,
        expire_in: 60 * 15
    }]
};

renderStatus(-1, "Generating user key pair");
KeyManager.generate_rsa({userid: "test user"}, function(err, user_km) {
    if (!err) {
        renderStatus(-1, "Self-signing user key pair");
        user_km.sign({}, function(err) {
            if (!err) {
                renderStatus(-1, "Exporting user public key");
                user_km.export_pgp_public({}, function(err, user_public) {
                    if (!err) {
                        renderStatus(-1, "Generating signing key pair");
                        KeyManager.generate(opts, function(err, km) {
                            if (!err) {
                                renderStatus(-1, "Self-signing key pair");
                                km.sign({}, function(err) {
                                    if (!err) {
                                        keys.key_pair.key_manager = km;
                                        renderStatus(-1, "Exporting private key");
                                        km.export_pgp_private({}, function(err, pgp_private) {
                                            if (!err) {
                                                keys.key_pair.private_key = pgp_private;
                                                renderStatus(-1, "Exporting public key");
                                                km.export_pgp_public({}, function(err, pgp_public) {
                                                    if (!err && user_km && !user_km.is_pgp_locked()) {
                                                        renderStatus(-1, "Signing public key with user key");
                                                        kbpgp.box({
                                                            msg: pgp_public,
                                                            sign_with: user_km
                                                        }, function(err, result_string) {
                                                            if (!err) {
                                                                keys.key_pair.signed_public_key = result_string;
                                                                renderStatus(-1, "Importing public key to key manager");
                                                                KeyManager.import_from_armored_pgp({armored: user_public}, function(err, km) {
                                                                    if (!err) {
                                                                        var ring = new kbpgp.keyring.KeyRing();
                                                                        ring.add_key_manager(km);
                                                                        renderStatus(-1, "Unboxing signed public key");
                                                                        kbpgp.unbox({keyfetch: ring, armored: keys.key_pair.signed_public_key}, function(err, literals) {
                                                                            if (!err) {
                                                                                var publicKey = literals[0].toString();
                                                                                KeyManager.import_from_armored_pgp({armored: publicKey}, function(err, skm) {
                                                                                    if (!err) {
                                                                                        renderStatus(0, "success");
                                                                                    } else {
                                                                                        renderStatus(1, "Unable to load session public key. Error: " + err);
                                                                                    }
                                                                                });
                                                                            } else {
                                                                                renderStatus(1, "Unable to verify signature on session public key");
                                                                            }
                                                                        });
                                                                    } else {
                                                                        renderStatus(1, "Unable to load public key");
                                                                    }
                                                                });
                                                            } else {
                                                                renderStatus(1, "Unable to sign key pair");
                                                            }
                                                        });
                                                    } else {
                                                        renderStatus(1, "Unable to export public key");
                                                    }
                                                });
                                            } else {
                                                renderStatus(1, "Unable to export private key. Error: " + err);
                                            }
                                        });
                                    } else {
                                        renderStatus(1, "Unable to self-sign key. Error: " + err);
                                    }
                                });
                            } else {
                                renderStatus(1, "Unable to generate key pair");
                            }
                        });
                    } else {
                        renderStatus(1, "Error exporting user public key");
                    }
                });
            } else {
                renderStatus(1, "Error self-signing user key pair");
            }
        });
    } else {
        renderStatus(1, "Unable to generate user key pair");
    }
});
