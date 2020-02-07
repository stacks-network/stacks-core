// https://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
var urlParams;
(window.onpopstate = function () {
    var match,
        pl     = /\+/g,  // Regex for replacing addition symbol with a space
        search = /([^&=]+)=?([^&]*)/g,
        decode = function (s) { return decodeURIComponent(s.replace(pl, " ")); },
        query  = window.location.search.substring(1);

    urlParams = {};
    while (match = search.exec(query))
       urlParams[decode(match[1])] = decode(match[2]);
})();

function makeHttpObject() {
  try {return new XMLHttpRequest();}
  catch (error) {}
  try {return new ActiveXObject("Msxml2.XMLHTTP");}
  catch (error) {}
  try {return new ActiveXObject("Microsoft.XMLHTTP");}
  catch (error) {}

  throw new Error("Could not create HTTP request object.");
}

function formatCode(body) {
   return "<div class=\"code\" align=\"left\">" + body + "</div>";
}

function formatNotGiven(body) {
   return "<div class=\"not-given\" align=\"left\">" + body + "</div>";
}

function makeOperationsTable(operations) {
   var tableData = "<table width=\"100%\">"
   for (var i = 0; i < operations.length; i++) {
      var txid = operations[i].txid;
      var opcode = operations[i].opcode;
      var address = operations[i].address;
      var name = operations[i].name;
      var op_fee = operations[i].op_fee;
      var token_fee = operations[i].token_fee;
      var namespace_id = operations[i].namespace_id;

      if (!token_fee) {
        token_fee = formatNotGiven("(no Stacks fee)");
      }
      else {
        token_fee = formatCode("uStacks: " + token_fee);
      }

      if (!op_fee) {
        op_fee = formatNotGiven("(no BTC fee)");
      }
      else {
        op_fee = formatCode("satoshis: " + op_fee);
      } 

      if (!name) {
        name = formatNotGiven("(no name)");
      }
      else {
        name = formatCode(name);
      }

      if (!namespace_id) {
        namespace_id = formatNotGiven("(no namespace)");
      }
      else {
        namespace_id = formatCode(namespace_id);
      }

      tableData += "<tr>";
      tableData += "<td>" + name + "</td>";
      tableData += "<td>" + namespace_id + "</td>";
      tableData += "<td>" + op_fee + "</td>";
      tableData += "<td>" + token_fee + "</td>";
      tableData += "</tr><tr>"
      tableData += "<td>" + formatCode(opcode) + "</td>";
      tableData += "<td>" + formatCode(address) + "</td>";
      tableData += "<td>" + formatCode(txid) + "</td>";
      tableData += "</tr>";
      tableData += "<tr><td colspan=\"4\"><hr/></td></tr>";
    }
    if (operations.length == 0) {
       tableData += "<tr><td colspan=\"4\">" + formatNotGiven("(no Blockstack transactions)") + "</tr>";
    }

    tableData += "</table>"
    return tableData;
}

function makeAtlasNeighborsTable(neighbors) {
   var tableData = "<table width=\"100%\">"
   for (var i = 0; i < neighbors.length; i++) {
      var atlasHost = neighbors[i].host;
      var atlasPort = neighbors[i].port;
      
      tableData += "<tr>";
      tableData += "<td>" + formatCode(atlasHost + ":" + atlasPort) + "<td>";
      tableData += "</tr>";
    }
    if (neighbors.length == 0) {
      tableData += "<tr><td colspan=\"2\">" + formatNotGiven("(no neighbor peers)") + "</tr>";
    }
    tableData += "</table>";
    return tableData;
}

function getBlockHeight() {
    var blockHeightRequest = makeHttpObject();
    blockHeightRequest.open("GET", "/blockHeight", true);
    blockHeightRequest.send(null);
    blockHeightRequest.onreadystatechange = function() {
        if (blockHeightRequest.readyState == 4) {
            var blockInfo = JSON.parse(blockHeightRequest.responseText);
            var blockHeight = blockInfo.blockHeight;
            var consensusHash = blockInfo.consensusHash;
            
            var blockHeightElem = document.getElementById("blockHeight");
            blockHeightElem.innerHTML = blockHeight;

            var chElem = document.getElementById("consensusHash");
            chElem.innerHTML = consensusHash;
        }
    }
}

function getBlockchainOperations() {
    var operationsRequest = makeHttpObject();
    operationsRequest.open("GET", "/operations");
    operationsRequest.send(null);
    operationsRequest.onreadystatechange = function() {
        if (operationsRequest.readyState == 4) {
            var operations = JSON.parse(operationsRequest.responseText);
            var operationsElem = document.getElementById("lastOperations");
            operationsElem.innerHTML = makeOperationsTable(operations);
        }
    }
}

function getAtlasNeighbors() {
    var atlasNeighborsRequest = makeHttpObject();
    atlasNeighborsRequest.open("GET", "/atlas-neighbors");
    atlasNeighborsRequest.send(null);
    atlasNeighborsRequest.onreadystatechange = function() {
        if (atlasNeighborsRequest.readyState == 4) {
            var neighbors = JSON.parse(atlasNeighborsRequest.responseText);
            var neighborsElem = document.getElementById("atlasNeighbors");
            neighborsElem.innerHTML = makeAtlasNeighborsTable(neighbors);
        }
    }
}

function getTestnetConfig() {
    var configRequest = makeHttpObject();
    configRequest.open("GET", "/config");
    configRequest.send(null);
    configRequest.onreadystatechange = function() {
        if (configRequest.readyState == 4) {
            var configData = JSON.parse(configRequest.responseText);
            for (var configItem of Object.keys(configData)) {
              var configElem = document.getElementById(configItem);
              configElem.innerHTML = configData[configItem];
            }
        }
    }
}

function getAddressBalance(addr) {
    var balanceRequest = makeHttpObject();
    balanceRequest.open('GET', '/balance/' + addr)
    balanceRequest.send(null);
    balanceRequest.onreadystatechange = function() {
        if (balanceRequest.readyState == 4) {
            var balanceData = JSON.parse(balanceRequest.responseText);
            var btcBalance = balanceData.btc;
            var stacksBalance = balanceData.stacks;
            
            document.getElementById('addressBTCBalance').innerHTML = 'BTC (satoshis): ' + btcBalance;
            document.getElementById('addressStacksBalance').innerHTML = 'Stacks (microStacks): ' + stacksBalance;
        }
    }
}


var namesPage = 0;
var namespacePage = 0;

function getNames(page) {
    var namesRequest = makeHttpObject();
    namesRequest.open('GET', '/names/' + page)
    namesRequest.send(null);
    namesRequest.onreadystatechange = function() {
        if (namesRequest.readyState == 4) {
            var namesList = JSON.parse(namesRequest.responseText);
            var namesHtml = '';
            for (var i = 0; i < namesList.length; i++) {
                namesHtml += '<div class="row">' + namesList[i] + '</div>';
            }

            // little hacky, but prevent overruns 
            if (namesList.length > 0) {
               document.getElementById('namesList').innerHTML = namesHtml;
            }
            else {
               namesPage = namesPage > 0 ? namesPage - 1: 0;
            }
        }
    }
}

function getNamespaces(page) {
    var namespaceRequest = makeHttpObject();
    namespaceRequest.open('GET', '/namespaces/' + page)
    namespaceRequest.send(null);
    namespaceRequest.onreadystatechange = function() {
        if (namespaceRequest.readyState == 4) {
            var namespaceList = JSON.parse(namespaceRequest.responseText);
            var namespaceHtml = '';
            for (var i = 0; i < namespaceList.length; i++) {
                namespaceHtml += '<div class="row">' + namespaceList[i] + '</div>';
            }

            // little hacky, but prevent overruns 
            if (namespaceList.length > 0) {
                document.getElementById('namespaceList').innerHTML = namespaceHtml;
            }
            else {
                namespacePage = namespacePage > 0 ? namespacePage - 1: 0;
            }
        }
    }
}

function nextNamespacePage() {
  namespacePage += 1;
  getNamespaces(namespacePage);
}

function prevNamespacePage() {
  namespacePage -= 1;
  if (namespacePage < 0) {
    namespacePage = 0;
  }
  else {
    getNamespaces(namespacePage);
  }
}

function nextNamesPage() {
  namesPage += 1;
  getNames(namesPage);
}

function prevNamesPage() {
  namesPage -= 1;
  if (namesPage < 0) {
    namesPage = 0;
  }
  else {
    getNames(namesPage);
  }
}

function getBitcoinTxid() {
  var bitcoinTxid = urlParams['bitcoinTxid'];
  if (!!bitcoinTxid) {
    var bitcoinTxidElem = document.getElementById("bitcoinTxid");
    bitcoinTxidElem.innerHTML = "TXID: " + bitcoinTxid;
  }
}

function getStacksTxid() {
  var stacksTxid = urlParams['stacksTxid'];
  if (!!stacksTxid) {
    var stacksTxidElem = document.getElementById("stacksTxid");
    stacksTxidElem.innerHTML = "TXID: " + stacksTxid;
  }
}

function loadStats() {
    getTestnetConfig();
    getBlockHeight();
    getBlockchainOperations();
    getAtlasNeighbors();
    getNames(0);
    getNamespaces(0);
}

document.addEventListener('DOMContentLoaded', function() {
  loadStats();
  getBitcoinTxid();
  getStacksTxid();
});

window.setInterval(loadStats, 30000);
// window.setInterval(loadStats, 1000);

