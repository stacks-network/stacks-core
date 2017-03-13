# generated in part from 'homebrew-pypi-poet'
# to generate:
# * create a virtualenv
# * pip install blockstack-client
# * pip install homebrew-pypi-poet
# * poet blockstack > /path/to/resources

class Blockstack < Formula
  desc "Blockstack command-line client"
  homepage "https://blockstack.org"
  url "https://files.pythonhosted.org/packages/8d/37/db5313cb8087a64fc1e783052c97d42ffa976e54d83b3181034c32fb428b/blockstack-0.14.1.1.tar.gz"
  sha256 "3c32edfcd702fb2db1e2e10e8d6b3c70e6aa68a8cddcaf0443d6b5c33a38fa54"

  # NOTE: must be added manually, after using `poet`
  depends_on :python if MacOS.version <= :snow_leopard
  depends_on "openssl"
  depends_on "libffi"

  resource "appdirs" do
    url "https://files.pythonhosted.org/packages/48/69/d87c60746b393309ca30761f8e2b49473d43450b150cb08f3c6df5c11be5/appdirs-1.4.3.tar.gz"
    sha256 "9e5896d1372858f8dd3344faf4e5014d21849c756c8d5701f78f8a103b372d92"
  end

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
    url "https://files.pythonhosted.org/packages/8d/37/db5313cb8087a64fc1e783052c97d42ffa976e54d83b3181034c32fb428b/blockstack-0.14.1.1.tar.gz"
    sha256 "3c32edfcd702fb2db1e2e10e8d6b3c70e6aa68a8cddcaf0443d6b5c33a38fa54"
  end

  resource "blockstack-profiles" do
    url "https://files.pythonhosted.org/packages/a7/72/04d52473b1960730d2a1c32183701d2e23322b762b9c4bc151a2ed890243/blockstack-profiles-0.14.1.tar.gz"
    sha256 "1c50cdf6e42a1cb058d39f9533903a30060bdc84f4c87de6275db7e1a928f72c"
  end

  resource "blockstack-zones" do
    url "https://files.pythonhosted.org/packages/df/c0/3ce945dda86c0d3df188f0196a2210957a0e257c03453a60b7f40e871ce1/blockstack-zones-0.14.1.tar.gz"
    sha256 "f84042ef7ad86f560ae01ca4a85d6c24571241f1ec54855c175cf6ca908f8276"
  end

  resource "boto" do
    url "https://files.pythonhosted.org/packages/b1/f9/cf8fa9a4a48e651294fc88446edee96f8b965f1d3ca044befc5dd7c9449b/boto-2.46.1.tar.gz"
    sha256 "d24a68d97276445d1b5baee6537bc565ab7070afcd449a72f2541b1da1328ed4"
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
    url "https://files.pythonhosted.org/packages/99/df/71c7260003f5c469cec3db4c547115df39e9ce6c719a99e067ba0e78fd8a/cryptography-1.7.2.tar.gz"
    sha256 "878cb68b3da3d493ffd68f36db11c29deee623671d3287c3f8d685117ffda9a9"
  end

  resource "defusedxml" do
    url "https://files.pythonhosted.org/packages/74/ba/4ba4e89e21b5a2e267d80736ea674609a0a33cc4435a6d748ef04f1f9374/defusedxml-0.5.0.tar.gz"
    sha256 "24d7f2f94f7f3cb6061acb215685e5125fbcdc40a857eff9de22518820b0a4f4"
  end

  resource "dropbox" do
    url "https://files.pythonhosted.org/packages/39/89/5e494728d66645cefa5ef21ac104fc0be12e512fe623e5c37bac1243fb88/dropbox-7.2.1.tar.gz"
    sha256 "acb85a33b4f977de11facb7516b4e0c9d5325920e71a2a26d39df383d34fefec"
  end

  resource "ecdsa" do
    url "https://files.pythonhosted.org/packages/f9/e5/99ebb176e47f150ac115ffeda5fedb6a3dbb3c00c74a59fd84ddf12f5857/ecdsa-0.13.tar.gz"
    sha256 "64cf1ee26d1cde3c73c6d7d107f835fed7c6a2904aef9eac223d57ad800c43fa"
  end

  resource "enum34" do
    url "https://files.pythonhosted.org/packages/bf/3e/31d502c25302814a7c2f1d3959d2a3b3f78e509002ba91aea64993936876/enum34-1.1.6.tar.gz"
    sha256 "8ad8c4783bf61ded74527bffb48ed9b54166685e4230386a9ed9b1279e2df5b1"
  end

  resource "fastecdsa" do
    url "https://files.pythonhosted.org/packages/35/2f/e476d9c4f902df5da29d7011f3f73c8f47cc65332f3773cf7f35afbee98a/fastecdsa-1.4.1.tar.gz"
    sha256 "60bebe1e9a7c7ab4a2199c3d2bfd88fd130529efd32778202f1bed56d564ed38"
  end

  resource "functools32" do
    url "https://files.pythonhosted.org/packages/c5/60/6ac26ad05857c601308d8fb9e87fa36d0ebf889423f47c3502ef034365db/functools32-3.2.3-2.tar.gz"
    sha256 "f6253dfbe0538ad2e387bd8fdfd9293c925d63553f5813c4e587745416501e6d"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/a3/06/40cb383eaea6e97047666db51abc2f2b32046f3e2a6e5ab2b946630f6062/idna-2.4.tar.gz"
    sha256 "2a07165f6288f4b920aa8ab4357c1e59073c5d62e048a400510982769e039bd9"
  end

  resource "ipaddress" do
    url "https://files.pythonhosted.org/packages/4e/13/774faf38b445d0b3a844b65747175b2e0500164b7c28d78e34987a5bfe06/ipaddress-1.0.18.tar.gz"
    sha256 "5d8534c8e185f2d8a1fda1ef73f2c8f4b23264e8e30063feeb9511d492a413e1"
  end

  resource "jsonpatch" do
    url "https://files.pythonhosted.org/packages/be/c1/947048a839120acefc13a614280be3289db404901d1a2d49b6310c6d5757/jsonpatch-1.15.tar.gz"
    sha256 "ae23cd08b2f7246f8f2475363501e740c4ef93f08f2a3b7b9bcfac0cc37fceb1"
  end

  resource "jsonpointer" do
    url "https://files.pythonhosted.org/packages/f6/36/6bdd302303e8bc7c25102dbc1eabb3e3d97f57b0f8f414f4da7ea7ab9dd8/jsonpointer-1.10.tar.gz"
    sha256 "9fa5dcac35eefd53e25d6cd4c310d963c9f0b897641772cd6e5e7b89df7ee0b1"
  end

  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/58/b9/171dbb07e18c6346090a37f03c7e74410a1a56123f847efed59af260a298/jsonschema-2.6.0.tar.gz"
    sha256 "6ff5f3180870836cae40f06fa10419f557208175f13ad7bc26caa77beb1f6e02"
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
    url "https://files.pythonhosted.org/packages/f1/14/04eb21ac61aae10971fbc550ca981dc91abb5c340a17ff7497c356e54654/keylib-0.1.0.tar.gz"
    sha256 "62133b85d465ed6eda7c9dec0ff293da822508efa2772ef8f0504381e29189ef"
  end

  resource "mixpanel" do
    url "https://files.pythonhosted.org/packages/bf/03/4413160bbe55ee64f0676cba2b787408b3c78d14ba4db52ba8334e39dfaf/mixpanel-4.3.2.tar.gz"
    sha256 "86e3fc54a496d009f6dee4f05598acd0afc6e81ccee8901fc3ca6c5194c29e44"
  end

  resource "packaging" do
    url "https://files.pythonhosted.org/packages/c6/70/bb32913de251017e266c5114d0a645f262fb10ebc9bf6de894966d124e35/packaging-16.8.tar.gz"
    sha256 "5d50835fdf0a7edf0b55e311b7c887786504efea1177abd7e69329a8e5ea619e"
  end

  resource "protocoin" do
    url "https://files.pythonhosted.org/packages/74/ac/18e6c67061166c42cf16381894b6b4f47a993b979fbeaff2f537d723dd55/protocoin-0.2.tar.gz"
    sha256 "616aeeb7a7f63a5f4a066cd4019788a4a327d80bd6fc59ce4a3c84222733eb0f"
  end

  resource "pyasn1" do
    url "https://files.pythonhosted.org/packages/69/17/eec927b7604d2663fef82204578a0056e11e0fc08d485fdb3b6199d9b590/pyasn1-0.2.3.tar.gz"
    sha256 "738c4ebd88a718e700ee35c8d129acce2286542daa80a82823a7073644f706ad"
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

  resource "pyparsing" do
    url "https://files.pythonhosted.org/packages/3c/ec/a94f8cf7274ea60b5413df054f82a8980523efd712ec55a59e7c3357cf7c/pyparsing-2.2.0.tar.gz"
    sha256 "0832bcf47acd283788593e7a0f542407bd9550a55a8a8435214a1960e04bcb04"
  end

  resource "python-bitcoinrpc" do
    url "https://files.pythonhosted.org/packages/2b/bd/54ce6bb445330df0938a91bc2bcac472142a5c57e3e0b329958992a352c4/python-bitcoinrpc-0.1.tar.gz"
    sha256 "6306ab38bb73d7399f2a037c53e2f63f4445ba336f85a8e4055f005f3bf3a97f"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/16/09/37b69de7c924d318e51ece1c4ceb679bf93be9d05973bb30c35babd596e2/requests-2.13.0.tar.gz"
    sha256 "5722cd09762faa01276230270ff16af7acf7c5c45d623868d9ba116f15791ce8"
  end

  resource "simplejson" do
    url "https://files.pythonhosted.org/packages/40/ad/52c1f3a562df3b210e8f165e1aa243a178c454ead65476a39fa3ce1847b6/simplejson-3.10.0.tar.gz"
    sha256 "953be622e88323c6f43fad61ffd05bebe73b9fd9863a46d68b052d2aa7d71ce2"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/b3/b2/238e2590826bfdd113244a40d9d3eb26918bd798fc187e2360a8367068db/six-1.10.0.tar.gz"
    sha256 "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a"
  end

  resource "typing" do
    url "https://files.pythonhosted.org/packages/b6/0c/53c42edca789378b8c05a5496e689f44e5dd82bc6861d1ae5a926ee51b84/typing-3.5.3.0.tar.gz"
    sha256 "ca2daac7e393e8ee86e9140cd0cf0172ff6bb50ebdf0b06281770f98f31bff21"
  end

  resource "urllib3" do
    url "https://files.pythonhosted.org/packages/20/56/a6aa403b0998f857b474a538343ee483f5c02491bd1aebf61d42a3f60f77/urllib3-1.20.tar.gz"
    sha256 "97ef2b6e2878d84c0126b9f4e608e37a951ca7848e4855a7f7f4437d5c34a72f"
  end

  resource "utilitybelt" do
    url "https://files.pythonhosted.org/packages/ab/31/343ef1df18ffe822f02b4ca879d1f406275d3187040ac724bcf9158e4669/utilitybelt-0.2.6.tar.gz"
    sha256 "dafdb6a2dbb32e71d67a9cd35afd7c2e4993ec094e7ddb547df4cf46788770a4"
  end

  resource "virtualchain" do
    url "https://files.pythonhosted.org/packages/a7/a4/2ae10e651520d184a94c9c2d1a93c44f65f64747302a4ac79a58358f7eca/virtualchain-0.14.1.tar.gz"
    sha256 "a26000ff5006a995b0ad9f0b58e19065634a6ace3a6971dfdc219828d183ed6c"
  end

  resource "warlock" do
    url "https://files.pythonhosted.org/packages/2d/40/9f01a5e1574dab946598793351d59c86f58209d182d229aaa545abb98894/warlock-1.3.0.tar.gz"
    sha256 "d7403f728fce67ee2f22f3d7fa09c9de0bc95c3e7bcf6005b9c1962b77976a06"
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
