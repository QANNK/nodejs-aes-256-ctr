// Nodejs encryption with CTR
var crypto = require('crypto');
algorithm = 'aes-256-ctr';

const key = Buffer.from('', 'hex');
const iv = Buffer.from('e9278e5f422d225ed6eb0de6d54e177c','hex');
const plainText = Buffer.from('26e11b9bf0bda9463402c5cd5bef71aa52d0d4c9625cc2e3e1470e4c','hex');

shasum = crypto.createHash('sha1');
shasum.update(plainText);

const sha1Auth = shasum.digest('hex');

function encrypt(buffer){
  var cipher = crypto.createCipheriv(algorithm,key,iv);
  var crypted = Buffer.concat([cipher.update(buffer),cipher.final()]);
  return crypted;
}
 
function decrypt(buffer){
  var decipher = crypto.createCipheriv(algorithm,key,iv);
  var dec = Buffer.concat([decipher.update(buffer) , decipher.final()]);
  return dec;
}

console.log('\nIV:', iv.toString('hex'));
console.log('\nplainText:', plainText.toString('hex'));
console.log('\nsha1Auth:', sha1Auth.toString('hex'));
var finalString = plainText.toString('hex')+sha1Auth.toString('hex');
var finalBuffer = Buffer.from(finalString,'hex');
console.log('\nplainText+sha1Auth:', finalBuffer.toString('hex'));
var hw = encrypt(finalBuffer);
console.log('\nencrypted:', hw.toString('hex'));
console.log('\ndecrypted:', decrypt(hw).toString('hex'));