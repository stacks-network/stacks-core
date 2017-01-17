# generated in part from 'homebrew-pypi-poet'
# to generate:
# * create a virtualenv
# * pip install blockstack-client
# * pip install homebrew-pypi-poet
# * poet blockstack > /path/to/resources

class Blockstack < Formula
  desc "Blockstack command-line client"
  homepage "https://blockstack.org"
  url null
  sha256 null

  # NOTE: must be added manually, after using `poet`
  depends_on :python if MacOS.version <= :snow_leopard
  depends_on "openssl"
  depends_on "libffi"

  resource "base58" do
    url "https://files.pythonhosted.org/packages/98/7f/41aba6037e8d578e0518b431ae7d2880eeee59f79265bddc554d0e504d66/base58-0.2.4.tar.gz"
    sha256 "97cb4dcbc7a81afb802f41033d5562b6c48633426a67bf41e4cad186f581158c"
  end

  resource "basicrpc" do
    url "https://files.pythonhosted.org/packages/ec/47/516aa9c118a437e833e604d3a35503cf55edcc991aba02d8505811976a57/basicrpc-0.0.2.tar.gz"
    sha256 "d471cd0a1f06766583c4b7d6cbae3ab9e2afeb64794b1cee94906cfb4da2a2af"
  end

  resource "bitcoin" do
    url "https://files.pythonhosted.org/packages/12/88/c9390638d5b2713d38ccea46c93e8ec084f052a15a94f9b1d4c66baabd24/bitcoin-1.1.42.tar.gz"
    sha256 "11ba70bd9e1c764f6bb2c4bd4c7fbebd5c9053c73f4d4325b00a98869a8b7236"
  end

  resource "bitmerchant" do
    url "https://files.pythonhosted.org/packages/a0/3c/3cc4b1f447cf0ea27c21a0e2e55adaf0064a8cd4b3294fb3c27ca27f6dd3/bitmerchant-0.1.8.tar.gz"
    sha256 "fba4c2091084ed0b4f9faac0ebbba8d255c5ccd3a18e7f877ce13aab71649ddc"
  end

  resource "blockstack" do
    url "https://files.pythonhosted.org/packages/bc/3d/bddcad2005a8b2b7dd0352a4d44e59e6ceac0e0537645aaebbd10b1e7d47/blockstack-0.14.0.4.tar.gz"
    sha256 "52c4fffaef757d0cf21e7a2cd0a09f5775335707211a276316c7cc2f8a07a49a"
  end

  resource "blockstack-profiles" do
    url "https://files.pythonhosted.org/packages/0f/5c/adcddc6ab396cb8be6d60a90f26782f480f1f0fdd32bfcce05739bdda5d1/blockstack-profiles-0.14.0.tar.gz"
    sha256 "f3ca680e6dd2e0cab79adfd08447bc09c0d3c3c8ddb18ca23086ae69b63c22b5"
  end

  resource "blockstack-zones" do
    url "https://files.pythonhosted.org/packages/72/d6/2784d9f70d230c09c9ca2aeb6b30b6776a1219677412219356192a6e7ad4/blockstack-zones-0.14.0.tar.gz"
    sha256 "dd90d78479ae2bdc8eaa2c42813d498d4e73986b34bf5f808127f7459812d3a2"
  end

  resource "boto" do
    url "https://files.pythonhosted.org/packages/68/4a/48b302989cbc3e6c64a16da5ec807bb7b36d8e8d3428579addde2eb1f671/boto-2.43.0.tar.gz"
    sha256 "de4449cdc671939ecea6121c05587b25e73ac0c057bf1278a44bbc1974d5fd94"
  end

  resource "cachetools" do
    url "https://files.pythonhosted.org/packages/dc/64/16cbf95e0ac473503c5dcd61aefbbab9f12e1875f40a0aaff566a1236ac4/cachetools-2.0.0.tar.gz"
    sha256 "715a7202240dc20dbe83abdb2d804d543e2d4f07af146f53c82166bd75f3a628"
  end

  resource "cffi" do
    url "https://files.pythonhosted.org/packages/a1/32/e3d6c3a8b5461b903651dd6ce958ed03c093d2e00128e3f33ea69f1d7965/cffi-1.9.1.tar.gz"
    sha256 "563e0bd53fda03c151573217b3a49b3abad8813de9dd0632e10090f6190fdaf8"
  end

  resource "commontools" do
    url "https://files.pythonhosted.org/packages/f9/f1/4ef3bdc0ee16d8cd578217f77f39f22a1cd9cb78f469d1ea8efe32b75f4b/commontools-0.1.0.tar.gz"
    sha256 "945d510c3950a693d6f7eb9328b18d3efc02bc38d1a89f28f4e9b7411fe9b0cb"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/d7/a2/b90736c37fd720db425c5e48d69da75a6eff6609b22d2123762f1ae8c5f5/cryptography-1.6.tar.gz"
    sha256 "4d0d86d2c8d3fc89133c3fa0d164a688a458b6663ab6fa965c80d6c2cdaf9b3f"
  end

  resource "defusedxml" do
    url "https://files.pythonhosted.org/packages/09/3b/b1afa9649f48517d027e99413fec54f387f648c90156b3cf6451c8cd45f9/defusedxml-0.4.1.tar.gz"
    sha256 "cd551d5a518b745407635bb85116eb813818ecaf182e773c35b36239fc3f2478"
  end

  resource "ecdsa" do
    url "https://files.pythonhosted.org/packages/f9/e5/99ebb176e47f150ac115ffeda5fedb6a3dbb3c00c74a59fd84ddf12f5857/ecdsa-0.13.tar.gz"
    sha256 "64cf1ee26d1cde3c73c6d7d107f835fed7c6a2904aef9eac223d57ad800c43fa"
  end

  resource "enum34" do
    url "https://files.pythonhosted.org/packages/bf/3e/31d502c25302814a7c2f1d3959d2a3b3f78e509002ba91aea64993936876/enum34-1.1.6.tar.gz"
    sha256 "8ad8c4783bf61ded74527bffb48ed9b54166685e4230386a9ed9b1279e2df5b1"
  end

  resource "functools32" do
    url "https://files.pythonhosted.org/packages/c5/60/6ac26ad05857c601308d8fb9e87fa36d0ebf889423f47c3502ef034365db/functools32-3.2.3-2.tar.gz"
    sha256 "f6253dfbe0538ad2e387bd8fdfd9293c925d63553f5813c4e587745416501e6d"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/fb/84/8c27516fbaa8147acd2e431086b473c453c428e24e8fb99a1d89ce381851/idna-2.1.tar.gz"
    sha256 "ed36f281aebf3cd0797f163bb165d84c31507cedd15928b095b1675e2d04c676"
  end

  resource "ipaddress" do
    url "https://files.pythonhosted.org/packages/bb/26/3b64955ff73f9e3155079b9ed31812afdfa5333b5c76387454d651ef593a/ipaddress-1.0.17.tar.gz"
    sha256 "3a21c5a15f433710aaa26f1ae174b615973a25182006ae7f9c26de151cd51716"
  end

  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/58/0d/c816f5ea5adaf1293a1d81d32e4cdfdaf8496973aa5049786d7fdb14e7e7/jsonschema-2.5.1.tar.gz"
    sha256 "36673ac378feed3daa5956276a829699056523d7961027911f064b52255ead41"
  end

  resource "jsontokens" do
    url "https://files.pythonhosted.org/packages/71/fe/27f5fc1f61f881b250e65a642eb62f0ac0daddb51fddd3ecb1c85e5f0a64/jsontokens-0.0.2.tar.gz"
    sha256 "c63c3a1ddb581a4696fec28eaddb755648144058d8fb369f72db8305de204e46"
  end

  resource "keychain" do
    url "https://files.pythonhosted.org/packages/a8/25/afa689ea2ca8254b52b0d3e5b4f35736bea6cba105d5c394eecf380b50de/keychain-0.1.4.1.tar.gz"
    sha256 "e3087ec79f46d8fb618c0d2dda7e474aaf36d98b08dcc3c2375ca8db95227bcd"
  end

  resource "keylib" do
    url "https://files.pythonhosted.org/packages/e0/8e/aac128d5facaac09109f147aaf02d77a6a0617a7724456264d9250723990/keylib-0.0.5.tar.gz"
    sha256 "e52878439862f8da9add6547d3fb81f7f9ecf0bb3012799738b98194dbe8862e"
  end

  resource "mixpanel" do
    url "https://files.pythonhosted.org/packages/3b/32/ab8eae3015cb3cb1285d128854357c579e4f6c6e5df174704f750f258e7a/mixpanel-4.3.1.tar.gz"
    sha256 "5647dc18ef2a34daae56bc8838bf1f72d0be184fc4bdc0dba6e4c8d00519aa22"
  end

  resource "protocoin" do
    url "https://files.pythonhosted.org/packages/74/ac/18e6c67061166c42cf16381894b6b4f47a993b979fbeaff2f537d723dd55/protocoin-0.2.tar.gz"
    sha256 "616aeeb7a7f63a5f4a066cd4019788a4a327d80bd6fc59ce4a3c84222733eb0f"
  end

  resource "pyasn1" do
    url "https://files.pythonhosted.org/packages/f7/83/377e3dd2e95f9020dbd0dfd3c47aaa7deebe3c68d3857a4e51917146ae8b/pyasn1-0.1.9.tar.gz"
    sha256 "853cacd96d1f701ddd67aa03ecc05f51890135b7262e922710112f12a2ed2a7f"
  end

  resource "pybitcoin" do
    url "https://files.pythonhosted.org/packages/67/78/d538af65c51032f5b06377baa9713b61e798fe04b96dce6386ca6391a02f/pybitcoin-0.9.9.tar.gz"
    sha256 "0348d65232d5299d8619f2e9a0b993a72b2ee3492a71612f61d490b754421371"
  end

  resource "pycparser" do
    url "https://files.pythonhosted.org/packages/be/64/1bb257ffb17d01f4a38d7ce686809a736837ad4371bcc5c42ba7a715c3ac/pycparser-2.17.tar.gz"
    sha256 "0aac31e917c24cb3357f5a4d5566f2cc91a19ca41862f6c3c22dc60a629673b6"
  end

  resource "pycrypto" do
    url "https://files.pythonhosted.org/packages/60/db/645aa9af249f059cc3a368b118de33889219e0362141e75d4eaf6f80f163/pycrypto-2.6.1.tar.gz"
    sha256 "f2ce1e989b272cfcb677616763e0a2e7ec659effa67a88aa92b3a65528f60a3c"
  end

  resource "python-bitcoinrpc" do
    url "https://files.pythonhosted.org/packages/2b/bd/54ce6bb445330df0938a91bc2bcac472142a5c57e3e0b329958992a352c4/python-bitcoinrpc-0.1.tar.gz"
    sha256 "6306ab38bb73d7399f2a037c53e2f63f4445ba336f85a8e4055f005f3bf3a97f"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/6e/40/7434b2d9fe24107ada25ec90a1fc646e97f346130a2c51aa6a2b1aba28de/requests-2.12.1.tar.gz"
    sha256 "2109ecea94df90980be040490ff1d879971b024861539abb00054062388b612e"
  end

  resource "simplejson" do
    url "https://files.pythonhosted.org/packages/40/ad/52c1f3a562df3b210e8f165e1aa243a178c454ead65476a39fa3ce1847b6/simplejson-3.10.0.tar.gz"
    sha256 "953be622e88323c6f43fad61ffd05bebe73b9fd9863a46d68b052d2aa7d71ce2"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/b3/b2/238e2590826bfdd113244a40d9d3eb26918bd798fc187e2360a8367068db/six-1.10.0.tar.gz"
    sha256 "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a"
  end

  resource "utilitybelt" do
    url "https://files.pythonhosted.org/packages/ab/31/343ef1df18ffe822f02b4ca879d1f406275d3187040ac724bcf9158e4669/utilitybelt-0.2.6.tar.gz"
    sha256 "dafdb6a2dbb32e71d67a9cd35afd7c2e4993ec094e7ddb547df4cf46788770a4"
  end

  resource "virtualchain" do
    url "https://files.pythonhosted.org/packages/7d/1a/cca9e6d30b82c708a2139cb5b410169bd2ae7d4a18e8b418ae5038fbb0d1/virtualchain-0.14.0.tar.gz"
    sha256 "c798818b4f31f015b658a61d53edb59bac88c3c478e17a20a23f4d83bccde2db"
  end


  def install
    ENV.prepend_create_path "PYTHONPATH", libexec/"vendor/lib/python2.7/site-packages"

    # NOTE: this extra path must be added manually, in order for cryptography to work (since it uses pkg_resources, which must be the one *brew* installed, not the OS X one (which is out of date))
    ENV.prepend_create_path "PYTHONPATH", "/usr/local/lib/python2.7/site-packages"

    %w[base58 basicrpc bitcoin bitmerchant blockstack-profiles blockstack-zones boto cachetools cffi commontools cryptography defusedxml ecdsa enum34 idna ipaddress jsontokens keychain keylib mixpanel protocoin pyasn1 pybitcoin pycparser pycrypto python-bitcoinrpc requests six utilitybelt virtualchain].each do |r|
      resource(r).stage do
        system "python", *Language::Python.setup_install_args(libexec/"vendor")
      end
    end

    ENV.prepend_create_path "PYTHONPATH", libexec/"lib/python2.7/site-packages"
    system "python", *Language::Python.setup_install_args(libexec)

    bin.install Dir[libexec/"bin/*"]
    bin.env_script_all_files(libexec/"bin", :PYTHONPATH => ENV["PYTHONPATH"])
  end

  test do
    false
  end
end
