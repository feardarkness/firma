var fs = require ('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;

var xml = '<?xml version="1.0" encoding="UTF-8"?><Object Id="06/07/2017 07:10:59" xmlns="http://www.w3.org/2000/09/xmldsig#"><Data xmlns=""><RequestHeader><Servicio>AGETIC</Servicio><Metodo>CONSULTA</Metodo><FechaRequerimiento>18/07/2017</FechaRequerimiento><HoraRequerimiento>09:59:52</HoraRequerimiento><Usuario>BUSA</Usuario><Password>12345678</Password></RequestHeader><RequestData><CPT>000000000009</CPT></RequestData></Data></Object>';
//var xml = '<?xml version="1.0" encoding="UTF-8"?><Object Id="06/07/2017 07:10:59" xmlns="http://www.w3.org/2000/09/xmldsig#"><Data xmlns=""><RequestHeader><Servicio>AGETIC</Servicio><Metodo>PAGO</Metodo><FechaRequerimiento>18/07/2017</FechaRequerimiento><HoraRequerimiento>17:44:44</HoraRequerimiento><Usuario>BUSA</Usuario><Password>12345678</Password></RequestHeader><RequestData><CPT>000000000001</CPT><Canal>UNINET</Canal><MontoTotal>35.00</MontoTotal><Moneda>Bolivianos</Moneda><Pagos><Pago><NumeroCuenta>200000505050</NumeroCuenta><NumeroOperacion>1111111</NumeroOperacion><FechaOperacion>18/07/2017</FechaOperacion><HoraOperacion>17:22:22</HoraOperacion><Monto>20.00</Monto></Pago><Pago><NumeroCuenta>200000606060</NumeroCuenta><NumeroOperacion>156791</NumeroOperacion><FechaOperacion>18/07/2017</FechaOperacion><HoraOperacion>17:33:33</HoraOperacion><Monto>15.00</Monto></Pago></Pagos></RequestData></Data></Object>';
function MyKeyInfo(publicKey, privateKey) {
	  this.getKeyInfo = function(key, prefix) {
      let onlyKey = publicKey.replace('-----BEGIN CERTIFICATE-----', '');
      onlyKey = onlyKey.replace('-----END CERTIFICATE-----', '');
      onlyKey = onlyKey.replace('-----BEGIN PUBLIC KEY-----', '');
      onlyKey = onlyKey.replace('-----END PUBLIC KEY-----', '');
      onlyKey = onlyKey.replace(/(\r\n|\n|\r)/gm,"");
      return "<X509Data><X509Certificate>"+onlyKey+"</X509Certificate></X509Data><KeyName>Ag3t1k</KeyName>";
	  };
	  this.getKey = function(keyInfo) {
	    return keyInfo;
	  };
	}

fs.readFile('./privada.pem', {encoding: 'utf-8'}, function(err, llavePrivada){
  if (err) console.log(err);
  fs.readFile('./publica.pem', {encoding: 'utf-8'}, function(err, llavePublica){
    if (err) console.log(err);
    var sig = new SignedXml();
    sig.addReference("//*[local-name(.)='Object']", ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315'], 'http://www.w3.org/2000/09/xmldsig#sha1');
    sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    sig.signingKey = llavePrivada;
    // sig.keyInfoProvider = new FileKeyInfo('./PublicaBUN.cer');
    sig.keyInfoProvider = new MyKeyInfo(llavePublica, llavePrivada);
    sig.computeSignature(xml, {
      location: { referenceNode: "//*[local-name(.)='Object']", action: "before" }
    });
    // movimiento del dom
    fs.writeFileSync("firmado.xml", sig.getSignedXml())
    // YqVhjCGLCSBWKG8UQECw55onWeo=
  });
});
