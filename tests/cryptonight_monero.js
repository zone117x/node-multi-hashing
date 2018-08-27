const Buffer = require('safe-buffer').Buffer
const multiHashing = require('../build/Release/multihashing')
const assert = require('assert')

var tests = [
	new Buffer('This is a test This is a test This is a test'),
	new Buffer('74d15836e33d14e164c2494648996eb5ed71a3ec2c72c2be225eda1b8a857aba', 'hex'),
	new Buffer('0157c5ee188bbec8975285a3064ee92065217672fd69a1aebd0766c7b56ee0bd', 'hex'),
	new Buffer('4cf1ff9ca46eb433b36cd9f70e02b14cc06bfd18ca77fa9ccaafd1fd96c674b0', 'hex'),
	new Buffer('Lorem ipsum dolor sit amet, consectetur adipiscing'),
	new Buffer('22ec483997cba20105378af3ec647ee5d20401d7df21c0bf4bf866bc55383e92', 'hex'),
	new Buffer('755d58e48e53f795a0ed6b27c794018372922e5d1a256cdbf9fc442f59f284c9', 'hex'),
	new Buffer('7d292e43f4751714ec07dbcb0e4bbffe2a7afb6066420960684ff57d7474c871', 'hex'),
	new Buffer('elit, sed do eiusmod tempor incididunt ut labore'),
	new Buffer('c5efc04bf88b450e86537dc046339b16d35133c4d905ec7fa16bd28a67c4f2fe', 'hex'),
	new Buffer('7158c9c0d5082df7f2ee236b994f385bd96fd09eda30e21643cb7351fd7301ce', 'hex'),
	new Buffer('335563425256edebf1d92dc342369c2f4770ebb4112ba975659bd8a0f210abd0', 'hex'),
	new Buffer('et dolore magna aliqua. Ut enim ad minim veniam,'),
	new Buffer('628c400e4712cecb44d88572e9e8bb9be9a1221da1cb52ff8eefaf4adcc172eb', 'hex'),
	new Buffer('7329cde3fbf98bec02578fcdcfeaf2cf11e2a1f105324f89c36470708bd6db16', 'hex'),
	new Buffer('47758e86d2f57210366cec36fff26f9464d89efd116fe6ef28b718b5da120801', 'hex'),
	new Buffer('quis nostrud exercitation ullamco laboris nisi'),
	new Buffer('a0351d7aa54c2e7c774695af86f8bbb859a0ef9b0d4f0031dd1df5ea7ccc752d', 'hex'),
	new Buffer('05066660ea3bc0568269cd95c212ad2bf2f2ced4e4cdb1f2bc5f766e88e4862b', 'hex'),
	new Buffer('48787b48d5c68f0c1dd825c32580af741cc0ee314f08133135c1e86d87a24a95', 'hex'),
	new Buffer('ut aliquip ex ea commodo consequat. Duis aute'),
	new Buffer('677b3a14c1875eda0ca0c3d6c340413848b1ab0bf9d448dddd5714cbc6d170b9', 'hex'),
	new Buffer('edc9f99dfd626ddc5604f8b387c7a88cc6fcb17cef46a3b917c2f8ffbd449982', 'hex'),
	new Buffer('93bdf47495854f7cfaaca1af8c0f39ef4a3024c10eb0dea23726b0e06ef29e84', 'hex'),
	new Buffer('irure dolor in reprehenderit in voluptate velit'),
	new Buffer('8a73c33ebfd11d78db984486a298149d034051c61cdaf6ff7e783e46a6763edf', 'hex'),
	new Buffer('44df1cbd33439b82f901bcad232f3908331330edad0c9b9af35d62f524fd92b4', 'hex'),
	new Buffer('a375a71d0541057ccc96719150dfe10b6e6f486b19cf4a0835e19605413a8417', 'hex'),
	new Buffer('esse cillum dolore eu fugiat nulla pariatur.'),
	new Buffer('021007fa46b46110e7dd6c7f1bb392499d7461950efd884e6bb4260d57906b6f', 'hex'),
	new Buffer('0fa9723e149c0772d16ae95b744186f419b48adcbfe685c99b53f6db44ba2668', 'hex'),
	new Buffer('163478a76f8f1432533fbdd1284d65c89f37479e54f20841c6ce4eba56c73854', 'hex'),
	new Buffer('Excepteur sint occaecat cupidatat non proident,'),
	new Buffer('d61f8a0722e9d38c691fe22613ef68c83a498dd24e3c382ee1abfa665d632371', 'hex'),
	new Buffer('90c71412c2ca0c2e5789a98fb7ce36179d3c7f8b164f9aa07df56d44c9e9e96d', 'hex'),
	new Buffer('356b0470c6eea75cad7a108179e232905b23bdaf03c2824c6e619d503ee93677', 'hex'),
	new Buffer('sunt in culpa qui officia deserunt mollit anim id est laborum.'),
	new Buffer('75a105029f6b8c00429c427ffc7a64d84dbcdf2728ce0d2df9133cef91c9f8d3', 'hex'),
	new Buffer('5944b5b0480e84dc233bcc37101c23077542433c868c67325e9c501cfd1b8151', 'hex'),
	new Buffer('a47e2b007dc25bb279e197a1b91f67ecebe2ddd8791cd32dd2cb76dd21ed943f', 'hex'),
];

for (var i = 0; i < 10; ++i)
{
	for (var variant = 0; variant <= 2; ++variant)
	{
		var hash = multiHashing['cryptonight'](tests[i * 4], variant);
		assert.deepEqual(hash, tests[i * 4 + variant + 1]);
	}
}
