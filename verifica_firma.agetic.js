var fs = require ('fs');
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
var select = require('xml-crypto').xpath;
var dom = require('xmldom').DOMParser;

fs.readFile('./firmado.xml', {encoding: 'utf-8'}, function(err, xmlFile){
  var xml = xmlFile;
  var doc = new dom().parseFromString(xml);
  if (err) console.log(err);
  fs.readFile('./publica.pem', {encoding: 'utf-8'}, function(err, certificado){
    if (err) console.log(err);

    var sig = new SignedXml();
    var signature = select(doc, "/*[name()='Signature']")[0];
    //sig.keyInfoProvider = new FileKeyInfo(certificado);
    sig.keyInfoProvider = new FileKeyInfo('./publica.pem');
    sig.loadSignature(signature);
    var res = sig.checkSignature(xml);
    if (!res) {
      console.log(sig.validationErrors);
    } else {
      console.log('===============================================================');
      console.log('validado!!!!!');
      console.log('===============================================================');
    }
  });
});