// usage: node nearfs-upload.js <dir> <signer-account>  (key read from ~/.config/near/sealed-testnet/<signer>.json)
// Needs web4-deploy@0.8.0 installed: npm i --prefix $WEB4 web4-deploy@0.8.0  (WEB4 defaults to <tmpdir>/web4)
const W = (process.env.WEB4 || require('path').join(require('os').tmpdir(), 'web4')) + '/node_modules/';
const fs = require('fs');
const req = require('module').createRequire(W + 'web4-deploy/bin/deploy');
const { connect, keyStores, Account, KeyPair } = req('near-api-js');
const { packToFs } = req('ipfs-car/pack/fs');
const { deployNEARFS } = require(W + 'web4-deploy/src/util/nearfs.js');
(async () => {
  const [dir, signer] = process.argv.slice(2);
  const cred = JSON.parse(fs.readFileSync(`${process.env.HOME}/.config/near/sealed-testnet/${signer}.json`));
  const config = require(W + 'web4-deploy/src/config')('testnet');
  const keyStore = new keyStores.InMemoryKeyStore();
  await keyStore.setKey(config.networkId, signer, KeyPair.fromString(cred.private_key));
  const near = await connect({ ...config, keyStore });
  const account = new Account(near.connection, signer);
  const tmp = fs.mkdtempSync('/tmp/sealed-car-');
  const { root } = await packToFs({ input: dir, output: `${tmp}/d.car`, wrapWithDirectory: false });
  const car = Buffer.from(fs.readFileSync(`${tmp}/d.car`));
  console.log('ROOT', root.toString());
  await deployNEARFS(account, car, { flags: { yes: true } });
  console.log('DONE', root.toString());
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
