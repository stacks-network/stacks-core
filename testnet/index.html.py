#!/usr/bin/env python2

import virtualchain

SCRIPTS = [
    "testnet.js",
    "jquery.min.js",
    "bootstrap.min.js",
]

CSS_PATHS = [
    "bootstrap.min.css",
    'testnet.css'
]

def attrs(**kw):
    for k in kw:
        assert '"' not in kw[k]

    kwstr = " ".join('{}="{}"'.format(k.strip('_'), kw[k]) for k in kw)
    return kwstr

def table(body, **kw):
    kwstr = attrs(**kw)
    return "<table {}>{}</table>".format(kwstr, body)

def tr(body, **kw):
    kwstr = attrs(**kw)
    return "<tr {}>{}</tr>".format(kwstr, body)

def td(body, **kw):
    kwstr = attrs(**kw)
    return "<td {}>{}</td>".format(kwstr, body)

def div(body, **kw):
    kwstr = attrs(**kw)
    return "<div {}>{}</div>".format(kwstr, body)

def span(body, **kw):
    kwstr = attrs(**kw)
    return "<span {}>{}</span>".format(kwstr, body)

def ol(body, **kw):
    kwstr = attrs(**kw)
    return '<ol {}>{}</ol>'.format(kwstr, body)

def ul(body, **kw):
    kwstr = attrs(**kw)
    return '<ul {}>{}</ul>'.format(kwstr, body)

def li(body, **kw):
    kwstr = attrs(**kw)
    return '<li {}>{}</li>'.format(kwstr, body)

def p(body, **kw):
    kwstr = attrs(**kw)
    return '<p {}>{}</p>'.format(kwstr, body)

def form(action, method, body, **kw):
    kwstr = attrs(**kw)
    return '<form action="{}" method="{}" {}>{}</form>'.format(action, method, kwstr, body)

def label(name, _for, **kw):
    kwstr = attrs(**kw)
    return '<label for="{}" {}>{}</label>'.format(_for, kwstr, name)

def textinput(name, default, **kw):
    kwstr = attrs(**kw)
    return '<input type="text" name="{}" default="{}" {}/>'.format(name, default, kwstr)

def submit(value, **kw):
    kwstr = attrs(**kw)
    assert '"' not in value
    return '<button type="submit" {}>{}</button>'.format(kwstr, value)


# UI
blockheight = "loading..."
consensus_hash = "loading..."
GAIA_READ_URL = "loading..."
GAIA_WRITE_URL = "loading..."
SUBDOMAIN_REGISTRAR_URL = "loading..."
TRANSACTION_BROADCASTER_URL = "loading..."
BITCOIN_JSONRPC_URL = "loading..."
BITCOIN_P2P_URL = "loading..."


url_set = div(
            div(
                div("Blockchain Height:", _class="col-sm-6", align="right") + div(blockheight, align="left", _class="code col-sm-6", _id="blockHeight"),
            _class="row") +
            div(
                div("Consensus Hash:", _class="col-sm-6", align="right") + div(consensus_hash, align="left", _class="code col-sm-6", _id="consensusHash"),
            _class="row") +
            div(
                div("Gaia read URL:", _class="col-sm-6", align="right") + div(GAIA_READ_URL, align="left", _class="code col-sm-6", _id="gaiaReadURL"),
            _class="row") +
            div(
                div("Gaia write URL:", _class="col-sm-6", align="right") + div(GAIA_WRITE_URL, align="left", _class="code col-sm-6", _id="gaiaWriteURL"),
            _class="row") +
            div(
                div("Transaction broadcaster:", _class="col-sm-6", align="right") + div(TRANSACTION_BROADCASTER_URL, align="left", _class="code col-sm-6", _id="transactionBroadcasterURL"),
            _class="row") +
            div(
                div("Subdomain registrar:", _class="col-sm-6", align="right") + div(SUBDOMAIN_REGISTRAR_URL, align="left", _class="code col-sm-6", _id="subdomainRegistrarURL"),
            _class="row") +
            div(
                div("Bitcoin JSON-RPC:", _class="col-sm-6", align="right") + div(BITCOIN_JSONRPC_URL, align="left", _class="code col-sm-6", _id="bitcoinJSONRPCURL"),
            _class="row") +
            div(
                div("Bitcoin P2P:", _class="col-sm-6", align="right") + div(BITCOIN_P2P_URL, align="left", _class="code col-sm-6", _id="bitcoinP2PURL"),
            _class="row"),
        _class="row")


fund_form = div(
                form("/sendBTC", "POST",
                    div(
                        label('Address:', 'btcAddress', _class='control-label col-sm-4') +
                        div(
                            textinput("addr", "", _class="form-control", _id="btcAddress"),
                        _class="col-sm-4"),
                    _class="form-group") +
                    div(
                        label('Satoshis:', 'btcAmount', _class='control-label col-sm-4') +
                        div(
                            textinput('value', '0', _class='form-control', _id='btcAmount'),
                        _class="col-sm-4"),
                    _class='form-group') +
                    div(
                        div(
                            submit('Fund address with Bitcoin', _class='btn btn-default'),
                        _class='col-sm-offset-3 col-sm-4'),
                    _class='form-group') +
                    div(
                        div(' ', _class='code col-sm-8 col-sm-offset-2', _align='center', _id='bitcoinTxid'),
                    ),
                _class="form-horizontal"),
            _class="row") + "<hr/>" + \
            div(
                form("/sendStacks", "POST",
                    div(
                        label('Address:', 'stacksAddress', _class='control-label col-sm-4') +
                        div(
                            textinput("addr", "", _class="form-control", _id="stacksAddress"),
                        _class="col-sm-4"),
                    _class="form-group") +
                    div(
                        label('microStacks:', 'stacksAmount', _class='control-label col-sm-4') +
                        div(
                            textinput('value', '0', _class='form-control', _id='stacksAmount'),
                        _class="col-sm-4"),
                    _class='form-group') +
                    div(
                        div(
                            submit('Fund address with Stacks', _class='btn btn-default'),
                        _class='col-sm-offset-3 col-sm-10'),
                    _class='form-group') +
                    div(
                        div(' ', _class='code col-sm-8 col-sm-offset-2', _align='center', _id='stacksTxid'),
                    ),
                _class="form-horizontal"),
            _class='row') + "<hr/>" + \
            div(
                div(
                    div(
                        label('Address:', 'queryAddress', _class='control-label col-sm-4') +
                        div(
                            textinput('addr', '', _class='form-control', _id='queryAddress'),
                        _class='col-sm-4'),
                    _class='form-group') +
                    div(
                        div(
                            submit('Get Balance', _class='btn btn-default', onclick="getAddressBalance(document.getElementById('queryAddress').value)"),
                        _class='col-sm-offset-3 col-sm-10'),
                    _class='form-group') +
                    div(
                        div(' ', _class='code col-sm-4 col-sm-offset-1', _id='addressBTCBalance') + div(' ', _class='code col-sm-4 col-sm-offset-2', _id='addressStacksBalance'),
                    _class='row'),
                _class='form-horizontal'),
            _class='row')
                

hello_world = div(
                div(
                    p('Welcome to the Blockstack blockchain testnet.  Here\'s how to get started:') + '<br>' +
                    ul(
                        li('Install the <code>feature/stacks-token</code> branch of <a href="https://github.com/blockstack/blockstack.js/tree/feature/stacks-transactions">blockstack.js</a>') +
                        li('Install the new <a href="https://github.com/jcnelson/cli-blockstack">Blockstack CLI</a>') +
                        li('Make a keychain with: ' + p('<code>$ blockstack-cli -t make_keychain</code>')) +
                        li('Use the Faucet below to fund your payment address with some Stacks') +
                        li('Register a name with: ' + p('<code>$ blockstack-cli -t register hello_world.id2 YOUR_OWNER_KEY YOUR_PAYMENT_KEY GAIA_READ_URL</code>')) +
                        li('Register a subdomain with: ' + p('<code>$ blockstack-cli -t register_subdomain hello_world.personal.id2 YOUR_OWNER_KEY GAIA_READ_URL SUBDOMAIN_REGISTRAR_URL</code>'))
                    ) +
                    p("You can find values for <code>GAIA_READ_URL</code> and <code>SUBDOMAIN_REGISTRAR_URL</code> in the Services panel.") +
                    p('<b>Tips and Tricks</b>' +
                        ul(
                            li('Testnet blocks are generated once every 60 seconds.  Your transactions may take that long to confirm.') +
                            li('Names take up to 10 blocks to register.') +
                            li('Subdomains take up to 10 blocks to register.') +
                            li('If you want to run your own subdomain registrar, register a name and read the instructions <a href="https://github.com/blockstack/subdomain-registrar">here</a>.') +
                            li('If you want to run your own Gaia hub, see <a href="https://github.com/blockstack/gaia">here</a>.')
                        )
                    ) +
                    p("<b>NOTE:</b> This server reboots every 24 hours."),
                _class='col-sm-offset-1 col-sm-10'),
              _class='row')


names_namespace_list = div(
                            div(
                                "<b>Names</b>",
                            _class="code col-sm-2 col-sm-offset-1", align='left') +
                            div(
                                "<b>Namespaces</b>",
                            _class="code col-sm-2 col-sm-offset-5", align='left'),
                        _class='row') + \
                        div(
                            div(
                                'loading...', _id='namesList',
                            _class='code col-sm-2 col-sm-offset-1') +
                            div(
                                'loading...', _id='namespaceList',
                            _class='code col-sm-2 col-sm-offset-5'),
                        _class='row')

main_body = div(
                div(
                    div(
                        div('<b>About</b>', _class='code text-center panel-heading panel-heading-custom') +
                        div(hello_world, _class='panel-body'),
                    _class='panel panel-default') +
                    div(
                        div("<b>Services</b>", _class="code text-center panel-heading panel-heading-custom") +
                        div(url_set, _class='panel-body'),
                    _class='panel panel-default') +
                    div(
                        div('<b>Faucet</b>', _class='code text-center panel-heading panel-heading-custom') + 
                        div(fund_form, _class='panel-body'),
                    _class='panel panel-default') +
                    div(
                        div('<b>Registered Names and Namespaces</b>', _class='code text-center panel-heading panel-heading-custom') +
                        div(names_namespace_list, _class='panel-body'),
                    _class='panel panel-default') +
                    div(
                        div('<b>Blockstack Transactions from the Last Block</b>', _class='code text-center panel-heading panel-heading-custom') +
                        div('loading...', _id='lastOperations', _class='panel-body'),
                    _class='panel panel-default') +
                    div(
                        div('<b>Testnet Peers</b>', _class='code text-center panel-heading panel-heading-custom') +
                        div('loading...', _id='atlasNeighbors', _class='panel-body'),
                    _class='panel panel-default'),
                _class='panel-group'),
            _class='container')

panel = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'
panel += "<html lang=\"en\"><head><title>Stacks Testnet</title>"

for s in CSS_PATHS:
    panel += '<link rel="stylesheet" href="{}">'.format(s)

for s in SCRIPTS:
    panel += '<script type="text/javascript" src="{}"></script>'.format(s)

panel += "</head><body>" + main_body + "</body></html>"

print panel
