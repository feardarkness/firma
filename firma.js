var fs = require ('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;

var xml = '<?xml version="1.0" encoding="UTF-8"?><Object Id="06/07/2017 07:10:59" xmlns="http://www.w3.org/2000/09/xmldsig#"><Data xmlns=""><ResponseHeader><Result>0000</Result><Message>Operacion exitosa</Message></ResponseHeader><ResponseData><CPT>AEDAD555</CPT><CI>10810779</CI><Nombre>AGUILERA KADO ANKEE</Nombre><MontoTotal>18.5</MontoTotal><Pagos><Pago><NumeroCuenta>156156156156</NumeroCuenta><NombreEntidad>Segip: servicio general de identificacion</NombreEntidad><Monto>18.5</Monto></Pago><Pago><NumeroCuenta>1000000YYYYYY</NumeroCuenta><NombreEntidad>ADUANA: Aduana nacional de bolivia</NombreEntidad><Monto>25</Monto></Pago></Pagos></ResponseData></Data></Object>';

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
