# JavaScript 区块链编程学习手册（二）

> 原文：[`zh.annas-archive.org/md5/FF38F4732E99A2380E8ADFA2F873CF99`](https://zh.annas-archive.org/md5/FF38F4732E99A2380E8ADFA2F873CF99)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：同步网络

在之前的章节中，我们构建了一个由五个节点组成的网络。每个节点都知道网络中的所有其他节点，这创建了一个去中心化的区块链网络。现在我们需要创建一个同步的网络，以便每个节点上的区块链都是相同的，数据在整个网络中是一致的。我们不能容忍在不同节点上运行不同版本的区块链，因为这将完全破坏区块链的目的。应该只有一个版本的区块链在每个节点上是一致的。因此，在本章中，让我们同步在第四章中构建的网络，*创建一个去中心化的区块链网络*。我们将通过在网络中的所有节点之间广播已挖掘的交易和新区块来实现这一点。

在本章中，将涵盖以下主题：

+   理解同步网络的需求

+   构建/transaction/broadcast 端点

+   重构`createTransaction`方法和`/transaction`端点

+   测试交易端点

+   更新挖矿信息

+   构建/receive-new-block 端点

+   测试新的和更新的/mine 端点

让我们开始同步网络。

# 理解同步网络的需求

让我们试着理解为什么网络需要同步。我们目前有一个由五个节点组成的去中心化区块链网络。这些节点之间的数据不一致；每个节点上的数据可能不同，这将导致区块链的目的失败。让我们通过一个例子来理解这种情况。在 Postman 中发送一个示例交易，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/95e23e83-399c-4276-8668-a3db6e116ee3.png)

通过单击“发送”按钮将此交易发送到托管在`localhost:3001`上的节点。此交易将出现在`localhost:3001/blockchain`的`pendingTransactions`数组中，您可以在以下截图中观察到：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b5479e71-514c-4ebf-b15e-858d0f704ec1.png)

现在，转到任何其他节点并检查发送的交易。我们将无法在这些节点的`pendingTransactions`数组中查看交易。发送的示例交易只会出现在`localhost:3001`节点中。它不会广播到网络中的任何其他节点。

在本章中，您要做的是重构/transaction 端点，以便每当创建交易时，它都会广播到所有节点。这意味着所有节点将具有相同的数据。我们需要做同样的事情来挖掘一个区块。让我们重构/mine 端点，以便每当挖掘出一个新块时，它也会广播到整个网络。这意味着整个网络是同步的，并且具有相同数量的区块。通过网络同步数据是区块链技术的一个重要特性。

# 重构 createNewTransaction 方法和/transaction 端点

在本节中，让我们通过将`createNewTransaction`方法拆分为两个独立的部分来重构。一部分将简单地创建一个新交易，然后返回该交易，另一部分将把新交易推送到`pendingTransactions`数组中。我们还将创建一个名为`/transaction/broadcast`的新交易端点。此端点将允许我们在整个区块链网络中广播交易，以便每个节点具有相同的数据，并且整个网络是同步的。

# 修改 createNewTransaction 方法

在这里，让我们将`createNewTransaction`方法拆分为两个独立的方法，修改如下：

1.  转到`dev/blockchain.js`文件中的`createNewTransaction`方法。我们在第二章中构建了这个方法，*构建区块链*中的*创建 createNewTransaction 方法*部分。参考以下`createNewTransaction`方法：

```js
Blockchain.prototype.createNewTransaction = function (amount, sender, recipient) {
    const newTransaction = {
        amount: amount,
        sender: sender,
        recipient: recipient,
    };
    this.newTransactions.push(newTransaction);
    return.this.getlastBlock() ['index'] + 1;
}
```

1.  让我们对该方法进行以下突出显示的修改：

```js
Blockchain.prototype.createNewTransaction = function (amount, sender, recipient) {
    const newTransaction = {
        amount: amount,
        sender: sender,
        recipient: recipient,
        transactionId: uuid().split('-').join('')
    };
    return newTransaction;
}
```

在这里，为每个交易添加了一个 ID。为了创建这个 ID，使用了一个唯一的字符串，这与我们在第三章中用于创建节点地址的方法非常相似，*通过 API 访问区块链*。

1.  使用`uuid`库创建 ID 的唯一字符串。因此，在`dev/blockchain.js`文件的开头，定义所有常量的地方，您需要添加以下代码行，以便在我们的项目中使用`uuid`库：

```js
const uuid = require('uuid/v1');
```

在修改后的方法中，您可以观察到添加了以下代码行，以为`transactionId`值创建唯一的字符串。这是实现`uuid`库的地方：

```js
transactionId: uuid().split('-').join('')
```

在这里，`.split()`函数将去除添加到唯一字符串的破折号，然后`.join()`函数将重新连接字符串，以输出每个交易的唯一`Id`。

# 构建 addTransactionToPendingTransactions 方法

接下来，我们需要将返回的`newTransaction`推送到区块链的`pendingTransactions`数组中。因此，让我们创建另一个名为`addTransactionToPendingTransactions`的方法：

1.  在`dev/blockchain.js`文件中，`addTransactionToPendingTransactions`方法将定义如下：

```js
Blockchain.prototype.addTransactionToPendingTransactions = function(transactionObj) {
};
```

1.  接下来，获取`transactionObj`并将其推送到区块链的`pendingTransactions`数组中：

```js
Blockchain.prototype.addTransactionToPendingTransaction = function(transactionObj) {
    this.pendingTransactions.push(transactionObj);

};
```

1.  然后，我们只需返回添加了交易的区块的索引：

```js
Blockchain.prototype.addTransactionToPendingTransaction = function(transactionObj) {
    this.pendingTransaction.push(transactionObj);
    return this.getLastBlock()['index'] + 1;
};
```

简而言之，我们修改了`createNewTransaction`方法，该方法创建一个新的交易，并返回该新交易。然后，我们创建了一个名为`addTransactionToPendingTransactions`的新方法。该方法接受一个`transactionObj`并将其添加到区块链上的`pendingTransactions`数组中。之后，我们只需返回添加了新交易的区块的索引。

# 构建/transaction/broadcast 端点

在本节中，让我们构建一个名为`/transaction/broadcast`的新端点。从现在开始，每当我们想要创建一个新的交易时，我们将访问此`/transaction/broadcast`端点。此端点将执行两项操作：

+   它将创建一个新的交易。

+   然后，它将向网络中的所有其他节点广播该新交易。

让我们按以下步骤创建端点：

1.  要添加此端点，请转到`dev/networkNode.js`文件，我们在其中定义了所有端点，并按以下方式添加新端点：

```js
app.post('/transaction/broadcast', function(req, res) )  {

});
```

1.  然后，为了使端点执行上述功能，将以下突出显示的代码添加到端点：

```js
app.post('/transaction/broadcast', function(req, res) )  {
    const newTransaction = bitcoin.createNewTransaction();

});
```

这里的`createNewTransaction()`方法是上一节中修改过的方法。

1.  `createNewTransaction()`方法接受`amount`、`sender`和`recipient`参数。对于我们的端点，让我们假设所有这些数据都被发送到`req.body`上。因此，这些参数将如下所示在以下代码中进行定义：

```js
app.post('/transaction/broadcast', function(req, res) )  {
    const newTransaction = bitcoin.createNewTransaction(req.body.amount, req.body.sender, req.body.recipient);

});
```

1.  接下来，让我们借助`addTransactionToPendingTransactions`方法将`newTransaction`变量添加到节点的`pendingTransactions`数组中。因此，在前面的代码行之后，添加以下行：

```js
bitcoin.addTransactionToPendingTransactions (newTransaction);
```

1.  现在，将新交易广播到网络中的所有其他节点。可以按以下方式完成：

```js
bitcoin.netowrkNodes.forEach(networkNodeUrl => {
    //...
});
```

1.  在这个`forEach`循环中，让我们定义广播交易的代码。为此，向网络中的所有其他节点的`/transaction`端点发出请求。因此，在循环内，添加以下行：

```js
const requestOptions = {

};
```

1.  然后，定义我们所有的选项，如下所示：

```js
const requestOptions = {
    uri: networkNodeUrl + '/transaction',
 method: 'POST',
 body: newTransaction,
 json: true
};
```

1.  接下来，让我们创建一个承诺数组，将所有请求推送到该数组中，以便我们可以同时运行所有请求。让我们在`forEach`循环之前定义数组如下：

```js
const requestPromises = []; 
```

1.  然后，在定义所有选项之后，进行请求如下：

```js
requestPromises.push(rp(requestOptions));
```

在这行代码之前，我们将把所有请求推送到`requestPromises`数组中。`forEach`循环运行后，我们应该在`requestPromises`数组中有所有我们定义的请求。

1.  接下来，让我们运行所有请求。在`forEach`循环之后，添加以下行：

```js
promise.all(requestPromises)
```

1.  最后，在所有请求运行后，我们将添加以下行：

```js
.then(data => {

});
```

1.  我们实际上不会使用所有这些请求返回的数据，但我们会发送一个响应，因为在这一点上，整个广播已经完成。因此，在上述代码块中，添加以下突出显示的代码：

```js
.then(data => {
    res.json({ note: 'Transaction created and broadcast successfully.'})
});
```

通过添加上述代码行，我们已成功完成了构建`/transaction/broadcast`端点。

# 重构/transaction 端点

在本节中，我们将重构`/transaction`端点，以便它可以与新的`/transaction/broadcast`端点完美配合。让我们应用以下步骤修改端点：

1.  首先，转到`dev/networkNode.js`文件，并删除`/transaction`端点中的所有内容。只有在进行广播时，才会访问`/transaction`端点。当访问`/transaction`端点时，`newTransaction`变量将作为数据发送。可以定义如下条件：

```js
app.post('/transaction', function(req, res) {
    const newTransaction = req.body;

};
```

在上面突出显示的行中，`newTransaction`变量通过`req.body`发送到`/transaction`端点。

1.  接下来，将新交易添加到接收调用的任何节点的`pendingTransactions`数组中。为此，将使用新的`addTransactionToPendingTransactions`方法。因此，在上述代码的后面，添加以下行：

```js
bitcoin.addTransactionToPendingTransactions();
```

1.  这个方法简单地接收`newTransaction`变量：

```js
bitcoin.addTransactionToPendingTransactions(newTransaction);
```

1.  现在，从`addTransactionToPendingTransactions`方法中，我们得到交易将被添加到的块的索引。让我们在新的`/transaction`端点中保存这个块索引。在上述代码的开始处，添加变量如下：

```js
const blockIndex = bitcoin.addTransactionToPendingTransactions(newTransaction);
```

1.  最后要做的是发送一个响应。在上述行之后，添加以下内容：

```js
res.json({ note: 'Transaction will be added in block ${blockIndex}.'});
```

我们现在已经完成了对`/transaction`端点的重构。

# 测试交易端点

让我们测试`/transaction/broadcast`和`/transaction`端点，确保它们能够正确配合工作。

对于这个测试，我们需要做的第一件事是将所有节点连接在一起，以构建一个网络。您可能还记得如何做到这一点，因为我们在第四章中学习过，*创建分散的区块链网络*。无论如何，我们将快速浏览一遍这些步骤，以便您记起来。

# 回顾如何创建网络

看一下以下步骤，了解如何连接所有节点：

1.  打开 Postman 并访问`/register-and-broadcast-node`路由。这可以在任何一个节点上完成。在我们的示例中，让我们使用`localhost:3001`。

1.  现在，在正文中，我们要通过传递其 URL 来向我们的网络添加一个新节点。让我们从第二个节点开始。看一下以下的截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/87b035cc-5c80-4530-bb18-f0aea1856317.png)

1.  然后，点击发送按钮发送请求。发送请求后，您将收到一个响应，上面写着“新节点已成功注册到网络”。您可以以相同的方式发送所有剩余的节点。

1.  要验证所有节点是否正确连接以形成网络，请转到浏览器，输入`localhost:3001/blockchain`在地址栏中，然后按*Enter*。您将在`networkNodes`数组中看到所有节点。

# 测试交易端点

现在区块链网络已经建立，让我们测试一下我们在之前部分创建的端点。

让我们创建一个交易并将其发送到`/transaction/broadcast`端点。返回到 Postman，命中端口为`3001`的节点的`/transaction/broadcast`端点。在这里，发送一些数据作为交易，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a2f60fb5-2915-4f33-8eed-905d7fcc8109.png)

您发送的交易数据可以是任意随机数据。我们只需要金额、发送方和接收方。一旦添加了交易数据，让我们点击发送按钮发送此请求。如果交易成功发送，将收到一个响应，上面写着“交易已成功创建和广播”。

现在，转到浏览器，您应该能够在网络的每个节点上看到我们创建的交易。让我们检查一下这是否有效。在浏览器的地址栏中，输入`localhost:3001/blockchain`，然后按*Enter*。您应该看到`pendingTransactions`数组中的交易数据，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3b969bc3-62c2-44e6-bedd-56cdbb94b9ad.png)

在这里，`pendingTransactions`数组中的交易现在也有一个以随机哈希开头的`transactionId`值。

接下来，打开另一个标签页，输入`localhost:3002/blockchain`在地址栏中，然后按*Enter*。您可以看到相同的交易数据可以在数组中看到：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2ba59d42-0dbb-4812-ba14-19c3db20d31e.png)

如果您转到网络中的其他节点，您可以对所有剩余节点进行类似的检查。您可以观察到每个节点的`pendingTransactions`数组中的相同交易数据。区块链网络中的每个节点现在都知道已创建新交易。

您也可以尝试使用其他交易数据测试端点。尝试将金额更改为`500`，将发送方和接收方的地址更改为随机哈希字符串，并尝试将此请求发送到托管在`localhost:3004`上的节点。这不会有任何影响，因为广播端点将交易数据发送到网络中的所有节点。因此，这个请求应该像上一个一样工作。在浏览器上检查响应，您应该能够看到两个具有不同交易 ID 的交易。

尝试使用不同的交易数据进行实验，以清楚了解`/transaction`和`/transaction/broadcast`端点的工作原理。

从测试中，我们可以得出结论，`/transaction/broadcast`端点和`/transaction`端点都按我们预期的那样正常工作。

在下一节中，我们将通过重构`/mine`端点来继续同步网络，以便它将新创建的新块广播到整个网络。

# 更新挖矿信息

同步网络所需的下一步是更新`/mine`端点。我们还将添加一个新的端点，称为`/receive-new-block`。有必要更新`/mine`端点，以便每当一个节点创建一个新块时，该新块被广播到网络中的所有其他节点。这意味着网络中的每个节点都知道已创建新块，并且托管区块链的所有节点保持同步。

# 更新后的挖矿流程

每当挖掘出一个新块时，它将在特定节点上被挖掘。为了理解更新后的挖矿流程，让我们假设我们希望一个托管在端口`3001`上的节点为区块链挖掘一个新块：

1.  首先，将在所选节点上命中`/mine`端点。当命中`/mine`端点时，通过工作证明创建一个新块。

1.  新块创建后，它将被广播到网络中的所有其他节点。所有其他节点将在其`/receive-new-block`端点接收到该新块。如下图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/47f680ef-e0fc-49c0-ba54-d009efa5bd36.png)

1.  广播完成后，整个网络将同步，并且所有节点将托管相同的区块链。

另一件事需要注意的是，当新区块被广播并且节点接收到它时，该新区块将在链验证该区块合法后被添加到链中。然后，节点清除其`pendingTransactions`数组，因为所有待处理交易现在都在它们刚刚收到的新区块中。

在接下来的几节中，我们将逐步构建整个过程。随着我们构建每个步骤，应该更容易看到所有内容是如何协同工作的。

# 重构`/mine`端点

通过实施以下步骤来重构`/mine`端点：

1.  转到`dev/networkNode.js`文件。在`/mine`端点中，在我们定义了`newBlock`变量的部分下面，让我们添加将新区块广播到网络中所有其他节点的功能。为此，请按照我们在前几节中介绍的相同过程进行，即循环遍历网络中的所有其他节点，向节点发出请求，并将`newBlock`变量作为数据发送：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {

})
```

前面的一行提到，对于每个`networkNodes`，我们将发出请求并发送`newBlock`。

1.  然后，我们需要发送一些请求选项。这些选项将定义如下：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {

 }; 

})
```

1.  该对象中的第一个选项是`uri`。我们要发送请求的`uri`将是`networkNodeUrl`和我们将要创建的新端点，即`/receive-new-block`。我们将在下一节中处理此端点：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block',   
    }; 

})
```

1.  要添加的下一个选项是将使用的方法，即`POST`方法：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block', method: 'POST',   
    }; 

})
```

1.  接下来，让我们发送将在`body`中的数据。我们还想发送一个`newBlock`实例：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block',method: 'POST',        body: { newBlock: newBlock }
    }; 

})
```

1.  最后，在`body`之后，将`json`设置为`true`，如下所示：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block',method: 'POST',       body: { newBlock: newBlock },
        json: true
    }; 

})
```

1.  之后，通过添加以下突出显示的代码，进行请求：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block',method: 'POST',       body: { newBlock: newBlock },
       json: true
    }; 
    rp(requestOptions)
})
```

1.  每次进行这些请求时，它都会返回一个 promise。通过添加以下突出显示的代码，让我们创建所有这些 promises 的数组：

```js
const requestPromises = [];
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/receive-new-block',method: 'POST',       body: { newBlock: newBlock },
       json: true
    }; 
    requestPromises.push(rp(requestOptions));
});
```

在我们的`forEach`循环运行后，我们应该有一个充满了 promises 的数组。

1.  接下来，让我们运行所有这些 promises。因此，在`forEach`块之后，添加以下代码：

```js
Promise.all(requestPromises)
.then(data => {
    // ....
})
```

所有请求运行后，我们希望在`.then(data => { })`内执行另一个计算。如果记得，当创建新交易时，挖矿奖励交易代码`bitcoin.createNewTransaction(12.5, "00", nodeAddress);`需要在整个区块链网络中广播。目前，当挖掘出新区块时，我们创建了一个挖矿奖励交易，但它没有广播到整个网络。为了广播它，请求将被发送到`/transaction/broadcast`端点，因为它已经具有广播交易的功能。我们只需使用传递的挖矿奖励交易数据调用此端点。

1.  然而，在传递挖矿奖励交易数据之前，我们需要一些请求选项：

```js
Promise.all(requestPromises)
.then(data => {
    const requestOptions = {
 uri: bitcoin.currentNodeUrl + '/transaction/broadcast',
 method: 'POST',
    };    

})
```

1.  `body`数据将作为对象发送。在`body`中，让我们添加挖矿奖励交易数据：

```js
Promise.all(requestPromises)
.then(data => {
    const requestOptions = {
        uri: bitcoin.currentNodeUrl + '/transaction/broadcast',
        method: 'POST',
        body: {
 amount: 12.5, 
 sender:"00", 
 recipient: nodeAddress
 }
    };    

})
```

1.  最后，在`body`之后，通过添加以下行将`json`设置为`true`：

```js
json: true
```

1.  然后，在`requestOptions`之后，让我们发送以下请求：

```js
return rp(requestOptions);
```

在`/mine`端点内部，正在进行一系列计算以创建新的区块。然后，一旦创建了新的区块，它将被广播到网络中的所有其他节点。广播完成后，在`.then`块内，将发出对`/transaction/broadcast`端点的新请求。此请求将创建一个挖矿奖励交易，然后节点将其广播到整个区块链网络。然后，在请求运行并完成所有计算后，将发送响应：成功挖掘新区块。

您可以在[`github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/networkNode.js`](https://github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/networkNode.js)上查看完整更新的 mine 端点代码。

# 构建/receive-new-block 端点

接下来要做的是构建我们在更新的/mine 端点中使用的/receive-new-block 端点。让我们开始构建这个端点：

1.  在`dev/networkNode.js`文件中，在`/register-and-broadcast-node`端点之前，定义`/receive-new-block`端点如下：

```js
app.post('/receive-new-block', function(req, res) {
};
```

1.  在此端点内，代码期望接收正在广播的新区块。让我们将新区块保存在一个变量中，如下面的代码所示：

```js
app.post('/receive-new-block', function(req, res) {
    const newBlock = req.body.newBlock;

};
```

1.  当所有其他节点接收到这个新区块时，它们需要检查它是否真的是一个真实的区块，并且是否正确地适应了链。为了验证这一点，检查`newBlock`上的`previousBlockHash`，以确保它等于链中最后一个区块上的哈希。为此，需要访问链中的最后一个区块：

```js
app.post('/receive-new-block', function(req, res) {
    const newBlock = req.body.newBlock;
   const lastBlock = bitcoin.getLastBlock(); 
};
```

1.  接下来，让我们测试链中最后一个区块的哈希是否等于`newBlock`实例中的`previousBlockHash`：

```js
  lastBlock.hash === newBlock.previousBlockHash; 
```

1.  这样，我们知道这个`newBlock`确实紧跟在链中的`lastBlock`之后。定义的前面语句将返回`true`或`false`。`true`或`false`值将保存在`correctHash`变量中：

```js
const correctHash = lastBlock.hash === newBlock.previousBlockHash;
```

1.  在进行上述检查之后，我们还希望确保`newBlock`具有正确的索引。这意味着`newBlock`的索引应该比链中的`lastBlock`高一个。添加以下检查：

```js
const correctIndex = lastBlock['index'] + 1 === newBlock['index'];
```

1.  接下来，根据`newBlock`是否合法需要采取两种不同的行动。如果`newBlock`是合法的，应该被接受并添加到链中。如果不合法，应该被拒绝。为了定义这个条件，让我们使用一个`if`-`else`语句：

```js
if (correctHash && correctIndex) {
    bitcoin.chain.push(newBlock);

}
```

1.  现在，由于`newBlock`已经被添加到链中，`pendingTransactions`数组需要被清空，因为待处理的交易现在已经在新区块中。因此，在`if`语句中，需要添加下一个条件如下：

```js
bitcoin.pendingTransaction = [];
```

1.  接下来，需要做的最后一件事是发送一个响应，表示该区块已被接受并添加到链中。在`if`语句中，在前面的行下面，添加以下响应：

```js
res.json({
    note: 'New block received and accepted.',
    newBlock: newBlock
})
```

1.  如果`newBlock`不合法并且未通过先前定义的任何测试，则在`else`语句中发送响应以指示该区块已被拒绝：

```js
else{
  res.json({
      note:'New block rejected.',
      newBlock: newBlock
  });  
}
```

通过添加上述条件，我们已经完成了/receive-new-block 端点的构建。

# 测试新的和更新的/mine 端点

让我们测试更新的/mine 端点和我们刚刚创建的/receive-new-block 端点。基本上，/mine 端点将为我们挖掘新的区块。它还将获取该区块并将其广播到整个区块链网络，以便每个节点都同步，并且所有节点都具有相同的区块和相同的数据。这是我们在测试/mine 端点时期望观察到的结果：

1.  要开始，您应该让所有五个节点都在运行。您还应该将它们连接在一起，以创建一个区块链网络。

1.  接下来，转到浏览器。这里要做的第一件事是选择一个节点来挖掘新的区块。我们有五个节点可供选择，但在我们的情况下，我们将坚持使用第一个节点。因此，在地址栏中键入`localhost:3001/mine`，然后按*Enter*。您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/23699e8a-d66a-44cb-9621-c9eb26d4a4a5.png)

矿端点似乎已经完美地工作了。响应表明新区块已经被成功挖掘和广播。您还可以在前面的屏幕截图中看到新的区块及其索引。

1.  让我们验证新区块是否已添加到网络中。首先，在第一个节点上进行验证。在浏览器中打开另一个标签页，输入`localhost:3001/blockchain`，然后按*Enter*。您可以看到新区块已添加到网络中，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/070cd0e5-35f0-4ba8-9d7b-eafda9c28a20.png)

在上述截图中，您可能还注意到`pendingTransactions`数组中存在一些交易。这些待处理交易实际上是我们刚刚挖掘的区块的挖矿奖励。更新的`/mine`端点定义了在创建新区块后应广播挖矿奖励交易。

从现在开始，每当创建新区块时，该区块的挖矿奖励将进入`pendingTransactions`数组，并将添加到下一个区块中。这就是比特币区块链中挖矿奖励的工作原理。在前两章中创建区块链时，我们将挖矿奖励直接放入了我们挖掘的区块中。现在区块链更加先进，我们拥有了一个去中心化的网络，遵循最佳实践并将挖矿奖励放入下一个区块对我们来说非常重要。

让我们回到`/mine`端点并继续测试。让我们检查网络内的其他节点，并验证挖掘的新区块是否已添加到这些节点中。此外，让我们检查生成的挖矿奖励是否也已广播到网络中的其他节点。

在浏览器中打开另一个标签页，输入`localhost:3002/blockchain`，然后按*Enter*。您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f734e62b-ecbf-42b6-92b6-4399269bacce.png)

在上述截图中，您可以看到端口为`3002`的节点接收到了新挖掘的区块，以及挖矿奖励交易。您可以验证网络中其余节点的情况。

现在让我们从另一个节点挖掘另一个区块。不要转到`localhost:3001`，而是在浏览器的地址栏中输入`localhost:3004/mine`，然后按*Enter*。将挖掘新的区块；输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/94a59daa-dcdc-4080-96ac-ada1e5e99ea6.png)

从上述截图中，您可以观察到这是第三个区块。这是正确的，因为我们已经挖掘了两个区块。在区块的`transactions`数组中，您可以看到我们从上一个区块获得的挖矿奖励。这笔交易是端口为`3001`的节点在挖掘上一个区块时生成的挖矿奖励。

让我们转到`localhost:3001/blockchain`，验证我们刚刚挖掘的新区块是否已添加到网络中。您将看到以下响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f4040f16-0989-4758-aff8-66b3416b0bca.png)

在此截图中，您可以观察到刚刚挖掘的新区块已添加到端口为`3001`的节点中。该区块的交易数组包括来自上一个区块的挖矿奖励。我们现在在`pendingTransactions`数组中也有一个新的挖矿奖励，这是在挖掘第三个区块时生成的。通过之前使用的类似验证过程，您可以检查我们挖掘的第三个区块是否已添加到所有剩余节点中。

从这些测试中，看起来`/mine`端点正在按照预期工作。它正在创建新区块并将其广播到整个网络。这意味着整个网络是同步的，并且具有完全相同的区块链数据，这对于区块链正常工作非常重要。

让我们进一步测试端点。转到 Postman，创建一些交易，然后广播它们。之后，让我们挖掘一个新的区块，以查看新交易是否已正确添加到区块链中：

1.  现在转到您的 Postman 并创建以下交易：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b1d4bf96-cfd8-465a-a696-bd85c8ebe6b6.png)

1.  接下来，为了广播交易，请访问`/transaction/broadcast`端点。您可以将此交易数据发送到任何节点，并且应该会广播到整个网络。在我们的示例中，让我们将此交易发送到端口`3002`上的节点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f5d8682a-6ae2-403d-a1a7-991f9fe295a4.png)

1.  现在，点击发送按钮。然后，您将收到响应，表示交易已成功创建和广播。

您也可以尝试进行其他交易，就像我们之前所做的那样，通过更改金额值和发送方和接收方的地址。另一个测试是将交易数据发送到不同的节点。

1.  现在，让我们返回浏览器，检查节点，以验证它们是否都收到了我们刚刚创建的交易。因为我们之前在浏览器中加载了节点`3001`，让我们刷新它。您应该会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/615252da-d04b-4aeb-8638-a48cb160e6aa.png)

从前面的屏幕截图中，您可以观察到该节点有我们创建的所有三笔交易，以及上一个区块中的挖矿奖励，都在`pendingTransactions`数组中。同样，您可以验证其他节点的`pendingTransaction`数组。因此，我们可以得出结论，我们创建的所有交易都被完美地广播到整个网络。

现在，让我们挖掘一个新的区块，以验证所有待处理的交易是否已添加到新的区块中。在本例中，让我们在`3003`节点上挖掘一个新的区块，方法是在新标签的地址栏中键入`localhost:3003/mine`。响应将指示区块已成功挖掘和广播：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/9f5d3c19-68fc-4856-8426-5ef408dbe097.png)

从前面的屏幕截图中，在`transactions`数组中，看起来我们创建的所有交易都存在于新挖掘的区块中。让我们去所有的节点，验证我们创建的交易是否已添加到新的区块中。在`localhost:3001`上，您可以观察到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/acb06fbf-885b-42cb-9e42-47f77aa2a7c1.png)

从这个屏幕截图中，我们可以观察到我们现在有了一个包含我们发送的所有交易的第四个区块。然后，如果您检查`pendingTransactions`数组，您会看到交易数据已被清除，并且新的挖矿奖励存在其中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f703b8ef-1858-413a-8d6d-fe11a57bacf7.png)

在本节中，我们在不同的节点上创建了一对新的交易。然后，这些交易成功地被广播到整个网络。然后，我们挖掘了一个新的区块，我们创建的所有交易都成功地添加到了新的区块中。除此之外，我们新挖掘的区块被广播到了区块链网络中的所有节点。我们整个网络中的所有节点现在都是同步的，并且都包含相同的区块链数据。

# 摘要

到目前为止，您在本书中取得了很大的成就。您已经创建了一个分散的区块链网络，目前正在五个节点上运行，并且您构建了功能，以同步整个网络，以便所有节点都具有完全相同的数据。这反映了区块链在实际应用中的功能。

在本章中，我们通过重构端点将整个区块链网络成功同步，将数据广播到网络中的所有节点。我们首先将`/createNewTransaction`方法的功能拆分为两个部分：`/createNewTransaction`方法和`addTransactionToPendingTransactions`方法。然后，我们构建了`/transaction/broadcast`端点，将新创建的交易广播到网络中的所有节点。我们还重构了`/transaction`端点，使得`/transaction/broadcast`端点和`/transaction`端点能够一起工作。在本章的后面，我们重构了`/mine`端点，并构建了一个新的端点`/receive-new-block`。借助这些端点，新创建的区块可以广播到网络中的所有节点。

在下一章中，我们将构建共识算法，以确保网络中的所有节点都能就区块链中应持有的正确数据达成一致。


# 第六章：共识算法

在本章中，我们将为区块链网络构建一个共识算法。共识算法是所有网络内的节点就哪些数据是正确的并应该保留在区块链中达成一致的一种方式。为了构建共识算法，我们首先将构建一个名为`chainIsValid`的新方法。这个方法将通过比较链中所有区块的所有哈希来简单验证区块链。之后，我们将构建一个`/consensus`端点，每当我们想使用共识算法时，我们将访问该端点。

在本章中，我们将学习以下内容：

+   共识算法是什么

+   构建和测试`chainIsValid`方法

+   构建和测试`/consesnsus`端点

所以，让我们开始共识算法。

# 共识算法是什么？

当构建区块链时，它正在数百或数千个节点之间运行，并且每个交易和每个被创建的区块都被广播到整个区块链网络。在这些广播过程中可能会出现问题，或者可能某个节点没有收到发生的某个信息或交易。

甚至在区块链网络中可能存在一个恶意行为者，他在他们的区块链副本上发送虚假信息或创建欺诈性交易，并试图将它们广播到整个网络，以说服每个人它们是合法交易。那么，我们如何解决这个问题，以便区块链网络中只有合法的区块？

这就是共识算法将帮助我们的地方。共识算法将为我们提供一种比较一个节点与网络中所有其他节点的方式，以确认我们在该特定节点上有正确的数据。目前有许多不同的共识算法被用于不同的区块链网络。对于我们的区块链网络，我们将创建一个实现*最长链规则*的共识算法。

基本上，*最长链规则*会查看单个节点和该节点上的区块链副本，将该节点上的链的长度与所有其他节点上的链的长度进行比较。在这种比较中，如果发现有一条链的长度比所选节点上的链长，算法将用网络中最长的链替换所选节点上的链。

使用这个方法的理论是，我们应该能够相信最长的链来保存正确的数据，因为创建该链的工作量最大。最长的链中包含最多的区块，每个区块都是通过工作证明进行挖掘的。因此，我们可以假设整个网络都为最长的链做出了贡献，因为这条链需要付出很多工作。因此，我们将使用实现最长链规则的共识算法。比特币区块链网络实际上在现实生活中实现了这个最长链规则。

# 构建 chainIsValid 方法

让我们开始构建共识算法，创建一个名为`chainIsValid`的新方法。这个方法将验证一条链是否合法。让我们开始构建这个方法：

1.  在`blockchain.js`文件中，在`proofOfWork`方法之后，让我们定义该方法如下：

```js
Blockchain.prototype.chainIsValid = function() {

}
```

1.  现在，这个方法将以`blockchain`作为参数，并且将返回`blockchain`是否有效：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {

}
```

当我们将它们与当前节点上托管的链进行比较时，我们将使用`chainIsValid`方法来验证网络中的其他链。为了验证区块链的合法性，我们只需遍历区块链中的每个区块，并验证所有哈希是否正确对齐。

你可能还记得第二章中提到的，当定义`createNewBlock`方法时，该方法包括`previousBlockHash`和`hash`属性。这个`hash`属性是当前区块的哈希值。为了构建`chainIsValid`方法，让我们遍历区块链中的每个区块，并确保给定区块的`previousBlockHash`属性与上一个区块中的哈希属性完全相同。让我们在方法内部定义这个条件如下：

1.  为了遍历区块链中的每个区块，我们将使用一个`for`循环：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {

       for (var i = 1; i < blockchain.length; i++) {

 }; 

};
```

1.  在这个`for`循环内，让我们比较当前区块和上一个区块：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {

       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
 const prevBlock = blockchain[i - 1];   
       };  

};
```

当我们在每次迭代中遍历整个链时，`currentBlock`将是`i`的值，`prevBlock`将是`i - 1`的值。

1.  接下来，我们只需比较`currentBlock`上的`previousBlockHash`属性与上一个区块上的哈希属性。为了做到这一点，在方法中定义以下条件：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {

       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
                const prevBlock = blockchain[i - 1];
                if (currentBlock['previousBlockHash'] !== prevBlock['hash']) // chain is not valid...

       };  

};
```

当涉及到我们提到的前一个条件时，如果它没有得到满足，那么我们知道链条是无效的，因为哈希值没有正确对齐。

1.  为了满足验证条件，当前区块上的`previousBlockHash`应该等于上一个区块的哈希。我们将在方法内部使用一个标志来表示上述条件，如下所示：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {
       let validChain = true; 
       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
                const prevBlock = blockchain[i - 1];
                if (currentBlock['previousBlockHash'] !== prevBlock['hash']) // chain is not valid...   
       };  

};
```

最初，`validChain`变量的值等于`true`。当我们遍历区块链并看到哈希值没有正确对齐时，我们会将`validChain`变量设置为`false`，以表示链条无效。

1.  现在让我们回到`if`语句。将上述条件添加到其中：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {
       let validChain = true; 
       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
                const prevBlock = blockchain[i - 1];
                if (currentBlock['previousBlockHash'] !== prevBlock['hash']) validChain = false;   
       };  

};
```

1.  在循环结束时，我们可以简单地返回一个`validChain`变量，如果链有效，则返回值为`true`，如果无效则返回`false`：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {
       let validChain = true; 
       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
                const prevBlock = blockchain[i - 1];
                if (currentBlock['previousBlockHash'] !==
                prevBlock['hash']) validChain = false;   
       };  
       return validChain;
};
```

1.  我们还要做的一件事是验证链中的每个区块是否都具有正确的数据。我们可以通过使用`hashBlock`方法重新计算`currentBlock`的哈希值来实现这一点。如果生成的哈希值以四个零开头，就像我们在第二章中看到的那样，那么我们知道所有数据都是有效的。然而，如果不是以四个零开头，那么我们知道区块内的数据肯定是无效的。

我们要做的就是遍历链中的每个区块，重新计算每个区块的哈希值，并确保每个哈希值以四个零开头。因此，在`for`循环内，让我们首先定义一个变量来提到这个条件：

```js
Blockchain.prototype.chainIsValid = function(blockchain) {
       let validChain = true; 
       for (var i = 1; i < blockchain.length; i++) {
                const currentBlock = blockchain[i];
                const prevBlock = blockchain[i - 1];
                const blockHash = this.hashBlock ();
                if (currentBlock['previousBlockHash'] !==
                prevBlock['hash']) validChain = false;   
       };  
     return validChain;
};
```

1.  `hashblock()`方法接受参数，如：`previousBlockhash`，`currentBlockData`和`nonce`。让我们现在传递这些参数：

```js
const blockHash = this.hashBlock (prevBlock['hash']);
```

1.  接下来，我们必须将`currentBlockData`作为参数传递，你可能还记得前一章中提到的，它包括`currentBlock`中的交易和`currentBlock`的索引：

```js
const blockHash = this.hashBlock(prevBlock['hash'], { transactions: currentBlock['transactions'], index: currentBlock['index'] } );
```

1.  最后，我们必须传递的最后一个参数是`nonce`：

```js
const blockHash = this.hashBlock (prevBlock['hash'], { transactions: currentBlock['transactions'], index: currentBlock['index'] } currentBlock['nonce']);
```

1.  定义这些参数后，我们应该将`currentBlock`的哈希存储在`blockHash`变量中。接下来，我们只需验证哈希是否以四个零开头。因此，在`for`循环内，我们将提到以下条件：

```js
if (blockHash.substring(0, 4) !== '0000') validChain = false;
```

现在，我们基本上是在遍历整个区块链，只是简单地检查两件事：

+   我们进行的一个检查是确保所有哈希值正确对齐。如果它们没有正确对齐，我们会指出链条无效。

+   我们正在进行的另一个检查是对每个区块进行哈希，并确保`blockHash`字符串以四个零开头。如果不是以四个零开头，那么我们指出链条无效。

现在`chainIsValid`方法基本上已经完成了。然而，您可能已经注意到的一个重要的事情是，我们还没有检查创世区块是否符合任何方法。在我们在前面的代码块中定义的循环中，我们从位置 1 开始，完全跳过了位置 0，即创世区块。创世区块是一种特殊的区块，因为我们自己制作了它，而没有进行工作证明：

1.  因此，为了验证创世区块，我们只需确保它具有我们最初放入其中的属性。因此，在`for`循环之外，我们将如下表述这个条件：

```js
const genesisBlock = blockchain[0];
```

1.  现在我们只是想检查并验证创世区块上的所有属性是否正确。如果您还记得在第二章中，我们定义了创世区块，我们为其分配了值，例如`nonce`，值为`100`，`previousBlockHash`，值为`0`，以及字符串 0 的`hash`。因此，现在让我们检查这些属性，以确保它们是正确的。在以下代码片段中，我们将上述代码添加到以下变量中：

```js
const genesisBlock = blockchain[0];
const correctNonce = genesisBlock['nonce'] === 100;
const correctPreviousBlockHash = genesisBlock['previousBlockHash'] === '0';
const correctHash = genesisBlock['hash'] === '0';
```

1.  最后，我们要验证创世区块中不应该有任何交易。因此，为了检查这一点，我们将提到以下条件：

```js
const correctTransactions = genesisBlock['transactions'].length === 0;
```

1.  现在，如果我们有一个合法的创世区块，那么我们定义的所有这些变量都应该是 true。如果任何这些变量无效，那么我们希望将`validChain`变量更改为`false`，以便我们知道区块链无效。让我们将这个条件表述如下：

```js
if (!correctNonce || !correctPreviousBlockHash || !correctHash || !correctTransactions) validChain = false;
```

提及这最后一个条件完成了`chainIsValid`方法。

# 测试`chainIsValid`方法

现在让我们通过实施以下步骤来测试`chainIsValid`方法：

1.  在`test.js`文件中，让我们导入区块链数据结构并创建一个名为`bitcoin`的区块链的新实例：

```js
const Blockchain = require('./blockchain');
const bitcoin = new Blockchain();
```

1.  接下来，让我们生成一个用于测试的区块链。我们将通过从其中一个服务器开始来实现这一点。因此，转到终端，输入`npn run node_1`并按*Enter*。然后您将收到响应，监听端口 3001。

1.  在节点`3001`上，现在让我们创建一个区块链并向其中添加一些数据，以便我们可以测试新的区块链。目前，节点`3001`上的区块链只有创世区块。因此，通过命中`/mine`端点，让我们向链中添加几个更多的区块。因此，在浏览器中，转到`localhost:3001/mine`以创建一个新的区块。

1.  现在，如果您转到`localhost:3001/blockchain`，您应该能够观察到新的区块如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a3128e28-2ca5-4d4c-9230-3a2d60f02ac4.png)

因此，在节点`3001`，我们现在有两个区块和一个待处理的交易，即挖矿奖励交易。

1.  接下来，让我们创建一些要添加到区块链中的交易。要添加交易，请转到 Postman，并在那里添加一些交易，如下截图所示。让我们将这些交易发送到`localhost:3001`，并且还要命中`/transaction/broadcast`端点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c5f1ba3a-78e6-4c7f-92ea-2250f6e4c496.png)

1.  您也可以向节点添加许多其他交易。

1.  一旦交易被添加，让我们通过访问`localhost:3001/mine`来挖掘一个新的区块。一旦新的区块被挖掘出来，访问`localhost:3001/blockchain`以验证该区块是否已被添加到网络中。您应该观察到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c071524a-1a7e-4d61-a52c-2c8e8b13735a.png)

您将看到节点`3001`包含了第三个区块，其中包含我们在区块中传递的所有交易数据。我们还有一个待处理的交易。

1.  接下来，让我们向节点`3001`添加几个更多的交易，然后在该节点上挖掘一个新的区块。您将看到与前面情况类似的输出。我们添加的新交易数据现在存在于我们挖掘的第四个区块中。请查看以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/09d6460c-e4dd-4817-8c48-4bb9e0a44ff5.png)

1.  接下来，让我们再挖掘两个没有任何数据的块。现在，我们有一个包含六个块的区块链。在这六个块中，有两个块中没有任何交易数据。

1.  复制`localhost:3001`上的整个区块链并将其粘贴到`test.js`文件中。然后，在`test.js`文件中粘贴数据后，让我们将该粘贴的文本保存为一个变量：

```js
const bc1 { //.... the entier blockchain that we copied and pasted };
```

1.  让我们使用`chainIsValid`方法来验证链的有效性。为了做到这一点，在`test.js`文件中，让我们提到以下内容：

```js
console.log('VALID:' , bitcoin.chainIsValid(bc1.chain));
```

1.  让我们保存`test.js`文件并运行它。

# 验证测试的输出

现在，当我们运行这个文件时，我们应该收到一个有效区块链的验证，因为我们没有篡改它，而是合法地使用了所有正确的方法创建它。让我们验证`chainIsValid`方法是否正常工作：

1.  前往终端并通过在终端中键入`^C`来取消之前正在运行的进程。

1.  一旦进程被取消，然后在终端中，让我们键入`node dev/test.js`并按*Enter*。由于我们没有篡改区块链，我们将得到`Valid: true`的反馈，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/4f4f5aaf-f460-4123-8ab2-0208c1b89d3e.png)

现在，让我们稍微篡改一下区块链，看看是否可以得到一个错误的返回值：

1.  在我们粘贴到`test.js`文件中的区块链数据中，让我们更改任一块中的一个哈希值，看看是否会使区块链无效。

1.  一旦你改变了任何块的哈希值，保存文件并再次运行测试。由于数据现在被篡改，你将得到`false`的反馈：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/fcd7a8f5-208d-46ad-aa38-386e4ee16451.png)

接下来，让我们在一个区块的交易数据中搞一些乱。如果我们更改了一个区块中的任何交易数据，那么链就不应该是有效的，我们应该收到测试的假反馈。

最后，让我们测试创世块，也就是链中的第一个块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c4a37b58-6b30-4c1e-b29b-ce2e15128b60.png)

在我们粘贴的区块链数据的`test.js`文件中，让我们将`nonce`值从 100 改为 10。保存文件并在终端中再次运行测试，我们应该得到返回的输出为`false`。由于我们在`test.js`文件中篡改了区块链中的数据，当我们运行测试时，我们得到了`false`的反馈。这表明区块链不再有效或合法，因为其中的数据已经被篡改。因此，从这个测试中我们可以得出结论，`chainIsValid`方法完全符合我们的预期。

# 对结果进行适当的微小修改

现在，我们需要做的一个小事情是帮助我们理解`chainIsValid`方法的工作原理，即记录每个块的`previousBlockHash`和`currentBlock`哈希值，以便我们自己进行比较。因此，在`chainIsValid`方法的`for`循环中，让我们在循环结束之前添加以下代码行：

```js
console.log('previousBlockHash =>', prevBlock [ 'hash']);
console.log('currentBlockHash =>', currentBlock [ 'hash']);
```

让我们保存这个修改并再次运行测试。这一次，当我们运行测试时，我们应该看到所有的哈希值被记录下来，这样我们就可以自己比较它们，看看这个方法内部到底发生了什么。运行测试后，你应该看到`previousBlockHash`和`currentBlockHash`的值，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/4c112ba0-73d8-4f9a-8e30-06a80fb3a2fb.png)

从前面的截图中，你可以观察到，对于每次迭代，`previousBlockHash`的值都与前一个块的`currentBlockHash`的值匹配。如果你看所有的哈希值，你会看到它们成对地被记录下来。从截图中，我们可以观察到我们有许多对相同的哈希值，这就是使区块链有效的原因。

# 构建/共识端点

现在，让我们构建`/consensus`端点，它将使用我们在上一节中构建的`chainIsValid`方法。执行以下步骤来构建端点：

1.  让我们转到`networkNode.js`文件，并在`/register-node-bulk`端点之后，定义`/consensus`端点如下：

```js
app.get('/consensus', function(req, res) { 

});
```

1.  接下来，在`/consensus`端点内，让我们向区块链网络中的每个其他节点发出请求，以获取它们的区块链副本，并将其与当前节点上托管的区块链副本进行比较：

```js
app.get('/consensus', function(req, res) {
        bitcoin.networkNodes.forEach(networkNodeUrl => {

 }); 

});
```

1.  在这个`forEach`循环内，让我们做与在前几章中定义其他端点时做过无数次的相同的事情。因此，我们首先要为请求定义一些选项，如下所示：

```js
app.get('/consensus', function(req, res) {
        bitcoin.networkNodes.forEach(networkNodeUrl => {
                const requestOptions = {
 uri: networkNodeUrl + '/blockchain',
 method: 'GET',
 json: true 
 }        

        });         

});
```

1.  在定义选项之后，我们需要`request-promise` `requestOptions`，并将所有这些请求推入一个承诺数组，因为每个请求都会向我们返回一个承诺：

```js
app.get('/consensus', function(req, res) {
        const requestPromises = [];
        bitcoin.networkNodes.forEach(networkNodeUrl => {
                const requestOptions = {
                        uri: networkNodeUrl + '/blockchain',
                        method: 'GET',
                        json: true 
                }        
                requestPromises.push(rp(requestOptions));
        });         

});
```

1.  一旦`forEach`循环运行后，我们将得到一个填满所有请求的数组。接下来，让我们按以下方式运行这些请求：

```js
app.get('/consensus', function(req, res) {
        const requestPromises = [];
        bitcoin.networkNodes.forEach(networkNodeUrl => {
                const requestOptions = {
                        uri: networkNodeUrl + '/blockchain',
                        method: 'GET',
                        json: true 
                }        
                requestPromises.push(rp(requestOptions));
        });         
        Promise.all(requestPromises) 
```

1.  然后，让我们使用从所有这些承诺中收到的数据。我们收到的这些数据将是来自网络中每个节点的区块链的数组。因此，在上述代码的后面，让我们定义如下的代码：

```js
.then(blockchains => {

});
```

1.  现在让我们遍历来自网络中其他节点的所有这些`blockchains`，并查看是否有一个比当前节点上托管的区块链副本更长的区块链。我们将从响应中获取的所有区块链中开始循环：

```js
.then(blockchains => {
        blockchains.forEach(blockchain => { 
 //....
 });
});
```

1.  基本上，在`forEach`循环内，我们要做的就是确定网络中其他节点的区块链是否比当前节点上托管的区块链更长。为了做到这一点，让我们定义一些变量来跟踪所有数据，如下所示。我们要定义的第一个变量是托管在当前节点上的区块链的长度：

```js
.then(blockchains => {
        const currentChainLength = bitcoin.chain.length;
        blockchains.forEach(blockchain => {                
            //....
        });
});
```

1.  接下来，让我们定义一个变量，如果在`blockchains`数组中遇到更长的区块链，它将发生变化。我们要定义的第一件事是`maxChainLength`变量：

```js
.then(blockchains => {
        const currentChainLength = bitcoin.chain.length;
        let maxChainLength = currentChainLength;
        blockchains.forEach(blockchain => {                
            //....
        });
});
```

1.  接下来，我们要定义一个名为`newLongestChain`的变量。最初，我们将把它设置为`null`：

```js
.then(blockchains => {
        const currentChainLength = bitcoin.chain.length;
        let maxChainLength = currentChainLength;
        let newLongestChain = null;
        blockchains.forEach(blockchain => {                
            //....
        });
});
```

1.  然后，我们要定义的最后一个变量将被称为`newPendingTransactions`。让我们最初将其设置为`null`：

```js
.then(blockchains => {
        const currentChainLength = bitcoin.chain.length;
        let maxChainLength = currentChainLength;
       let newLongestChain = null;
        let newPendingTransactions = null;
        blockchains.forEach(blockchain => {                
            //....
        });
});
```

1.  现在，在`forEach`循环内，我们要查看区块链网络中是否存在比当前节点上更长的链。如果网络中存在更长的链，那么改变上述变量以反映这一点。因此，在`forEach`循环内，定义如下的`this`条件：

```js
.then(blockchains => {
        const currentChainLength = bitcoin.chain.length;
        let maxChainLength = currentChainLength;
       let newLongestChain = null;
        let newPendingTransactions = null;
        blockchains.forEach(blockchain => {                
            if (blockchain.chain.length > maxChainLength) {
 maxChainLength = blockchain.chain.length;
 newLongestChain = blockchain.chain;
 newPendingTransactions =
 blockchain.pendingTransactions;
 };    
        });
});
```

现在，在`forEach`循环运行后，我们将拥有确定是否需要替换托管在当前节点上的链所需的所有数据。接下来，在循环之后，让我们定义以下条件：

```js
if (!newLongestChain || (newLongestChain &&
    !bitcoin.chainIsValid(newLongestChain))) 
{
         res.json({
             note: 'Current chain has not been replaced.',
             chain: bitcoin.chain
         });
}
```

基本上，在这个`if`语句中我们要表达的是，如果没有`newLongestChain`，那么当前链就是最长的。或者，如果有一个新的最长链，但是这个新链无效，那么在这两种情况下，我们都不想替换托管在当前节点上的区块链。因此，我们将发送回一个说明“当前链未被替换”的通知。

否则，如果有一个`newLongestChain`并且该链是有效的，那么现在我们要用网络中最长的链替换托管在当前节点上的区块链。我们将在 else 块中定义所有这些内容，如下所示：

```js
else {
         bitcoin.chain = newLongestChain;
         bitcoin.pendingTransactions = newPendingTransactions;
         res.json({
                       note: 'This chain has been replaced.',
                       chain: bitcoin.chain
         });
}
```

# 构建过程的快速回顾

在这个端点中，我们首先向网络中的所有其他节点发出请求，以便我们可以访问每个节点上托管的区块链。在我们运行了所有这些请求之后，我们就可以访问网络中所有其他节点上托管的所有区块链。然后，我们通过`forEach`循环遍历网络中所有其他区块链。当我们遍历其他区块链时，如果我们找到了更长的链，我们就会更新`maxChainLength`、`newLongestChain`和`newPendingTransactions`变量以反映出这一点。然后，当`forEach`循环完成时，我们就会知道网络中是否存在比当前节点上托管的区块链更长的链。如果在网络中找到了更长的链，我们将能够访问该区块链的`pendingTransactions`。因此，在`forEach`循环运行后，我们将能够访问所有必要的数据，以替换当前节点上托管的错误区块链。

然后，我们说明了是否存在新的更长链，或者是否存在比当前节点上托管的区块链更长的链。如果在网络中存在更长的链，但该链无效，那么在这两种情况下，我们都不希望替换当前节点上托管的区块链，因此我们只需发送一个响应，说明当前链未被替换。

另一方面，如果在网络中存在更长的链，并且该链是有效的，那么我们将希望替换当前节点上托管的区块链。我们只需发送一个响应，说明该链已被替换，并返回新的区块链。

这就是共识算法和/consensus 端点的工作原理。

# 测试/consensus 端点

让我们测试刚刚构建的共识端点。因此，这个/consensus 端点应该做什么？当我们在特定节点上调用/consensus 端点时，它应该为我们确认该特定节点是否具有正确的区块链数据，并且该节点与网络的其余部分是同步的。让我们开始构建测试：

1.  我们的第一步是建立一个由前四个节点组成的网络。因此，让我们去 Postman，并在托管在`3001`上的节点上点击 register-and-broadcast-node 端点。

1.  让我们像下面的屏幕截图中所示，将第二个节点添加到网络中。然后，我们将点击发送按钮，接收到响应，成功注册新节点到网络：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b368c45a-4c9b-49aa-ace6-1b2a3e3f4dd4.png)

1.  同样地，您可以将剩余的节点`3003`和`3004`注册到网络中。现在，如果您去浏览器并检查所有节点，您将观察到从`3001`到`3004`的所有节点都相互连接，但节点 3005 没有连接。

1.  接下来，我们想要在区块链网络上挖掘一些区块，除了第五个节点。因此在浏览器中，让我们访问`localhost:3001/mine`。这将在节点`3001`上为我们挖掘一个区块。

1.  同样地，让我们在`localhost:3003`上挖掘两个区块，在`localhost:3004`上挖掘一个区块。现在，所有这些节点应该都有五个区块。您可以通过在浏览器中输入`localhost:3001/blockchain`来验证这一点。您将能够观察到我们刚刚添加的所有五个区块。

1.  在这一点上，我们想要将第五个节点连接到区块链网络。因此，让我们去 Postman 并发送 3005 的请求，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3a0f7b07-9868-4e2f-92c0-8b6130b79835.png)

1.  现在，节点`3005`应该已连接到网络。您可以通过浏览器验证这一点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/4deb4518-9e54-48d6-9a9e-43308078d02b.png)

现在`3005`是网络的一部分，问题就出现在这里：节点`3005`在区块链中没有正确的区块数据。它应该拥有其他节点拥有的所有五个区块。这就是`/consensus`端点发挥作用的地方。我们应该能够访问`/consensus`端点并解决这个问题。在这之后，我们应该期望节点`3005`上的区块链与网络中的其他所有节点具有相同的数据。

现在让我们试一试。在浏览器中打开另一个标签，并在地址栏中输入`localhost:3005/consensus`，然后按下*Enter*运行它。您应该观察到类似于以下截图中所见的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a8383833-ebe7-4d79-be6e-8b982678c0c2.png)

在前面的截图中，我们得到了响应，链已被替换，然后新的区块链数据取代了这个节点上的旧数据。让我们通过在浏览器中打开另一个标签并访问`localhost:3005/blockchain`来验证这个节点。您会看到网络中存在的所有区块都已经添加到节点`3005`中。因此，节点`3005`现在拥有了正确的区块链数据。我们通过访问节点`3005`上的`/consensus`端点来实现了这一点。现在，区块链网络中的所有节点应该具有完全相同的数据。

现在，如果你再次尝试在`3005`节点上访问`/consensus`端点，我们将会得到以下响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/bab9a994-3b0a-4dd0-82dc-7ad083b82423.png)

我们收到这样的响应，是因为在之前运行共识端点时，网络中已经存在的所有区块都已经添加到节点`3005`中。

通过这个测试，我们可以得出结论，`/consensus`完美地按预期工作。`/consensus`端点有能力在区块链中纠正节点的错误数据。

建议您尝试使用`/consensus`端点以不同的方式进行测试。向数据添加一些交易，并确保它能够正确解决持有错误数据的节点。通过更多地测试这个端点，您将更加熟悉它在底层是如何工作的。

# 摘要

所有的区块链都有共识算法，在本章中，我们构建了自己的共识算法，实现了最长链规则。我们首先构建了`chainIsValid`方法。在这个方法中，我们简单地遍历了区块链中的每一个区块，并比较了每个区块上的哈希值，以确保它们是正确的。然后我们继续测试这个方法。除此之外，我们利用`chainIsValid`方法构建了`/consensus`端点。

在下一章中，我们将构建一个区块浏览器，我们将能够在浏览器上访问。这个区块浏览器将允许我们通过用户界面与区块链进行交互。


# 第七章：区块浏览器

在这一章中，让我们构建一个区块浏览器，它将允许我们与区块链进行交互。区块浏览器只是一个用户界面，它将允许我们探索区块链内部的数据。它将允许我们搜索特定的区块、特定的交易或特定的地址，然后以视觉上吸引人的格式显示特定的信息。

构建区块浏览器的第一步是向区块链添加一些新的方法和端点，以便搜索数据。然后，让我们为区块浏览器添加一个前端，以便我们可以在浏览器中使用它。

在本章中，我们将涵盖以下主题：

+   什么是区块浏览器？

+   定义区块浏览器端点

+   构建`getBlock`、`getTransaction`和`getAddressData`方法

+   构建和测试`/block/:blockHash`、`/transaction/:transactionId`和`/address/:address`端点

+   开发我们的区块浏览器界面并对其进行测试。

因此，让我们开始构建我们的区块浏览器。

# 什么是区块浏览器？

区块浏览器是一个在线平台，允许您浏览区块链，搜索包括地址、区块、交易等各种内容。例如，如果您访问[`www.blockchain.com/explorer`](https://www.blockchain.com/explorer)，您可以看到比特币和以太坊区块链的区块浏览器实用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/5baf74be-82e9-42eb-b497-9bac04387285.png)

在这个区块浏览器内，您可以搜索整个区块链以获取特定的区块、哈希或交易，或者任何其他所需的数据片段。该实用程序还在易于理解的界面上显示结果。例如，如果我们在区块浏览器中搜索`Block #549897`，您将看到该特定区块的所有细节，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/66f3d303-52cf-44c6-bf65-355a9aa66818.png)

这正是我们将在本章中为我们的区块链构建的内容。

# 定义区块浏览器端点

为了使区块浏览器正常运行，我们需要查询区块链以获取地址、区块哈希和交易 ID，以便我们可以搜索特定的参数并得到相应的数据。因此，我们需要执行的第一步是构建一些新的端点。为此，让我们继续以下步骤：

1.  转到`dev/networkNode.js`文件，在`/consensus`端点之后，让我们定义我们的区块浏览器的第一个端点`/block/:blockHash`，如下所示：

```js
app.get('/block/:blockHash', function(req, res) { 

});
```

通过这个端点发送一个特定的`blockHash`，结果将简单地返回与输入的`blockHash`对应的区块。

1.  我们将构建的下一个端点将是`/transaction/:transactionId`。定义如下：

```js
app.get('/transaction/:transactionId', function(req, res) {

});
```

通过这个端点发送一个`transactionId`，作为回应，我们应该期望得到与该 ID 对应的正确交易。

1.  最后，我们将构建的第三个端点是`/address/:address`，定义如下：

```js
app.get('/address/:address', function(req, res) {

});
```

通过这个端点，我们将发送一个特定的地址，作为回应，您应该期望得到与该地址对应的所有交易——每当这个特定地址发送或接收比特币时——您还将了解到该地址的当前余额，即该地址当前拥有多少比特币。

因此，在本章中，您将构建这三个端点。对于这些端点中的每一个，我们将在区块链数据结构中构建一个特定的方法，该方法将查询区块链以获取正确的数据片段。因此，让我们创建查询区块链特定区块哈希、交易和地址的方法。

# 构建 getBlock 方法

让我们构建一个名为`getBlock`的新方法，该方法将获取给定的`blockHash`并搜索整个区块链，以找到与该特定哈希相关联的区块。为了构建`getBlock`方法，请按照以下步骤进行：

1.  转到`dev/blockchain.js`文件，在`chainIsValid`方法之后，定义如下新方法：

```js
Blockchain.prototype.getBlock = function(blockHash) { 

};
```

1.  在这个方法中，我们要遍历整个区块链，搜索具有特定`blockHash`值的区块。然后，该方法将把该特定区块返回给我们。我们将借助`for`循环来完成所有这些操作：

```js
Blockchain.prototype.getBlock = function(blockHash) { 
    this.chain.forEach(block => {

 });
};
```

在定义`for`循环时，我们遍历区块链中的每个区块。

1.  接下来，在循环内，使用`if`语句来说明条件，如下所示：

```js
Blockchain.prototype.getBlock = function(blockHash) { 
    this.chain.forEach(block => {
            if (block.hash === blockHash) 
    });
};
```

1.  为了表示我们正在寻找的正确区块已找到，我们将使用一个标志。让我们按照以下代码中的突出显示定义此标志变量：

```js
Blockchain.prototype.getBlock = function(blockHash) { 
    let correctBlock = null;
    this.chain.forEach(block => {
            if (block.hash === blockHash) 
    });
};
```

1.  当我们遍历链中的所有区块时，如果找到正确的区块，我们将把它赋给`correctBlock`。让我们按照以下条件来说明：

```js
Blockchain.prototype.getBlock = function(blockHash) { 
  let correctBlock = null;
    this.chain.forEach(block => {
            if (block.hash === blockHash) correctBlock = block;  
    });
};
```

1.  最后，在此方法的末尾，我们要返回`correctBlock`，如下所示：

```js
Blockchain.prototype.getBlock = function(blockHash) { 
  let correctBlock = null;
    this.chain.forEach(block => {
            if (block.hash === blockHash) correctBlock = block;  
    });
    return correctBlock
};
```

# 构建`/block/:blockHash`端点

在`/block/:blockHash`端点内使用`getBlock`方法来通过`blockHash`检索特定区块。让我们按照以下步骤构建端点：

1.  在此端点中，我们要做的第一件事是使用发送到`/block/:blockHash`请求的`blockHash`值。我们可以在`req.params`对象上访问此`blockHash`。转到`dev/networkNode.js`文件，并在先前定义的`/block/:blockHash`端点中添加以下突出显示的代码：

```js
app.get('/block/:blockHash', function(req, res) { 
        const blockHash = req.params.blockHash;
});
```

基本上，当我们访问`/block/:blockHash`端点时，我们正在访问网络中特定节点上存在的区块的哈希值。我们还将使用`req.params`对象来访问哈希值，这将使我们能够访问`/block/:blockHash` URL 中带有冒号的任何值。因此，当用户向此端点发出请求时，他们将在 URL 中发送一个`blockHash`，然后我们可以借助`req.params.blockHash`来获取该`blockHash`。然后，我们将保存该值在`blockHash`变量中。

1.  接下来，在端点内，我们要使用在上一节中创建的`getBlock`方法。我们将在端点中添加该方法，如下面的代码所示：

```js
app.get('/block/:blockHash', function(req, res) { 
        const blockHash = req.params.blockHash; const correctBlock = bitcoin.getBlock(blockHash);
});
```

到了代码的这一点，我们正在寻找的区块应该存在于`correctBlock`变量中。

1.  最后，将`correctBlock`变量作为响应发送回去，因此让我们在端点中添加以下突出显示的代码：

```js
app.get('/block/:blockHash', function(req, res) { 
        const blockHash = req.params.blockHash;const correctBlock = bitcoin.getBlock(blockHash);
        res.json({
 block: correctBlock
 });
});
```

这就是我们使用`getBlock`方法构建`/block/:blockHash`端点的方式。现在，让我们测试此端点并验证其是否正常工作。

# 测试`/block/:blockHash`端点

为了测试`/block/:blockHash`端点，请按照以下步骤进行：

1.  首先检查区块链中有多少个区块。转到浏览器，输入`localhost:3001/blockchain`，然后按*Enter*。您将看到区块链中存在的单个创世区块，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/07ae3071-7127-4c90-abc0-4b25590ee71d.png)

1.  您需要向此链中添加几个区块。要做到这一点，转到浏览器中的另一个标签页，输入`localhost:3001/mine`，然后按*Enter*。使用相同的过程，让我们生成一个更多的区块。现在我们应该在链中有三个区块：一个创世区块和我们刚刚添加的两个区块。

1.  为了测试`/block/:blockHash`端点，让我们简单地取其中一个区块的哈希值并用它来测试端点。让我们复制链中第三个区块的哈希值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/df0bf9b7-fb4e-4fae-a841-8f93b5d4badf.png)

1.  接下来，转到浏览器中的另一个标签页。在地址栏中键入`localhost:3001/block`，然后粘贴我们直接复制的哈希值。查看以下截图以更好地理解：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/dac61c7b-8feb-4906-90fa-6023e74418f0.png)

1.  现在，我们知道我们使用的哈希存在于链中的第三个区块中。因此，我们应该期望通过运行`/block/:blockHash`端点来返回第三个区块。现在按*Enter*，正确的区块应该作为输出返回给我们：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2ce260e8-54bf-4db5-b9cd-dd8ebb5ca4ce.png)

从上面的截图中，我们可以观察到正确的区块已经返回给我们。返回的区块包括我们在`/block/:blockHash`端点中使用的哈希值来搜索区块。

以类似的方式，您现在可以尝试使用端点和特定区块的哈希值来搜索链中的另一个区块。

现在，如果我们发送错误的哈希或在端点中不存在的哈希，我们应该期望得到 null 作为输出，而不是返回区块。让我们尝试通过向`/block/:blockHash`端点发送错误的哈希值来验证这一点。在浏览器的地址栏中，键入`localhost:3001/block`，然后添加一个虚假的哈希值并按*Enter*。应返回以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/cbfea903-4249-41e4-9bc0-d02b67b8ebb3.png)

从上面的截图中，您可以观察到`block`等于`null`。这意味着用于搜索区块的哈希值在链中不存在。因此，从测试中，我们可以得出结论，`/block/:blockHash`端点完全按预期工作。

# 定义 getTransaction 方法

让我们在区块链数据结构上添加一个名为`getTransaction`的新方法。这将允许我们通过传递`transactionId`来获取特定交易。我们将在`/transaction/:transactionId`端点内使用这个新方法。所以，让我们开始吧！

1.  转到`dev/blockchain.js`文件，在`getBlock`方法之后，定义`getTransaction`如下：

```js
Blockchain.prototype.getTransaction = function(transactionId) { 

}):
```

这个方法与`getBlock`方法非常相似。在这里，我们将遍历整个链，并将一个标志设置为我们正在寻找的正确交易。

1.  构建此方法的下一步是遍历整个区块链。为此，使用`forEach`循环如下所示：

```js
Blockchain.prototype.getTransaction = function(transactionId) { 
       this.chain.forEach(block => { 

 });

}):
```

1.  由于在这个方法中，我们正在寻找交易，我们需要遍历链中每个区块上的每个交易。因此，我们需要在前面的`for`循环内添加另一个`for`循环：

```js
Blockchain.prototype.getTransaction = function(transactionId) { 
       this.chain.forEach(block => { 
               block.transactions.forEach(transaction => { 

 });
       });

});
```

1.  现在，我们可以访问区块链上的每个交易，我们只需要将每个交易的`transactionId`与我们正在寻找的`transactionId`进行比较。当两者匹配时，我们就知道找到了正确的交易。让我们在循环内定义这个条件如下：

```js
Blockchain.prototype.getTransaction = function(transactionId) { 
       this.chain.forEach(block => { 
               block.transactions.forEach(transaction => { 
                       if (transaction.transactionId === transactionId) {

 }; 
               });
       });

});
```

1.  接下来，就像我们在`getBlock`方法内部所做的那样，我们希望在`getTransaction`方法内部设置一个标志，以指示我们已经找到了正确的交易。因此，在两个循环的顶部，定义标志变量并如下使用它：

```js
Blockchain.prototype.getTransaction = function(transactionId) {
       let correctTransaction = null; 
       this.chain.forEach(block => { 
               block.transactions.forEach(transaction => { 
                       if (transaction.transactionId === transactionId) {
                               correctTransaction = transaction;         

                       }; 
               });
       });

});
```

1.  现在，为了使这个方法更有用一些，我们还将发送回我们找到所需交易的区块。为此，定义另一个标志如下：

```js
let correctBlock = null;
```

1.  如果我们找到了正在寻找的交易，将条件设置如下：

```js
Blockchain.prototype.getTransaction = function(transactionId) {
       let correctTransaction = null;
       let correctBlock = null;  
       this.chain.forEach(block => { 
               block.transactions.forEach(transaction => { 
                       if (transaction.transactionId === transactionId) {
                             correctTransaction = transaction;         
                               correctBlock = block; 
                       }; 
               });
       });

});
```

1.  最后，要做的最后一件事就是将两个变量作为输出返回。让我们在两个循环之外定义这个返回条件如下：

```js
return {
         transaction: correctTransaction,
         block: correctBlock
};
```

# 构建/transaction/:transactionId 端点

让我们使用在上一节中构建的`getTransaction`方法来构建`/transaction/:transactionId`端点。让我们开始吧：

1.  在这个端点内部要做的第一件事是存储作为请求参数发送的交易 ID。让我们将其存储在一个`transactionId`变量中，如下所示：

```js
app.get('/transaction/:transactionId', function(req, res) {
         const transactionId = req.params.transactionId;
});
```

1.  接下来要做的是在端点内部使用`getTransaction`方法。为此，请将以下内容添加到前面的代码中：

```js
app.get('/transaction/:transactionId', function(req, res) {
         const transactionId = req.params.transactionId;
         bitcoin.getTransaction(transactionId);   

});
```

1.  从`getTransaction`方法中，我们得到一个包含我们正在寻找的交易和该交易所在的区块的对象。我们希望将这些数据存储在一个名为`transactionData`的变量中，如下所示：

```js
app.get('/transaction/:transactionId', function(req, res) {
         const transactionId = req.params.transactionId;
         const trasactionData = bitcoin.getTransaction(transactionId);  

});
```

1.  最后，我们希望发送一个简单的响应，其中包含`transactionData`变量：

```js
app.get('/transaction/:transactionId', function(req, res) {
         const transactionId = req.params.transactionId;
         const trasactionData = bitcoin.getTransaction(transactionId);
         res.json({
    transaction: trasactionData.transaction,
    block: trasactionData.block
         });   

});
```

这就是我们构建`/transaction/:transactionId`端点的方式。

# 测试`/transaction/:transactionId`端点

现在，是时候测试`/transaction/:transactionId`端点，以验证它是否按预期工作。但在这之前，我们需要向区块链添加一些交易数据和区块。

# 向区块链添加新的交易和区块

与前一部分类似，首先让我们向区块链添加一些交易和区块：

1.  因此，转到 Postman，点击`localhost:3001/transaction/broadcast`端点，将交易发送到网络中的所有节点。

1.  现在，向网络发送一些示例交易。您可以按照以下截图中所示的方式创建交易：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/29aa69ad-2785-4e2d-a2e8-7f039885ffdf.png)

1.  添加交易数据后，单击发送按钮将交易发送到网络。同样，您可以添加另一笔`"amount": 200`的交易并将其发送到网络。

1.  接下来，挖掘一个新的区块，以便将这些交易添加到区块链中。在浏览器中打开一个标签，输入`localhost:3001/mine`到地址栏。然后将创建新的区块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/0a0a8015-acf5-462c-886c-f45802e60ed5.png)

1.  接下来，发送另一个“amount”: 300 的交易，并使用先前提到的过程将其发送到网络。一旦交易发送完毕，让我们再次挖掘一个区块，将交易添加到区块链中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/6f6e4015-5fd2-4c53-85b9-4051ab8b2b7d.png)

1.  现在，添加另外两笔交易，分别为`"amount": 400`和`500`，并将其发送到网络。最后，再次挖掘一个区块，将我们现在创建的交易添加到区块链中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2af27f07-d285-48b6-ab63-e86236a03fef.png)

现在，如果您转到`localhost:3001/blockchain`，您将看到我们刚刚添加到区块链中的所有区块和交易。

# 测试端点

在向区块链添加交易和区块后，让我们测试`/transaction/:transactionId`端点：

1.  转到浏览器，打开另一个标签。在地址栏中输入`localhost:3001/transaction/`，然后在 URL 的末尾添加一个来自区块链中任何一个区块的`transactionId`值，然后按 Enter。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/22e3aba2-af6c-417c-a6f1-fba0ea3db39e.png)

1.  运行此端点后，应返回以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/6ce1d2b7-fce4-4a00-a821-e489f7289d30.png)

在前面的截图中，您可以看到我们使用端点传递的`transactionId`关联的交易作为输出。我们还返回了包含我们正在寻找的特定`transactionId`的区块。

1.  现在，使用一个在区块链中不存在的`transactionId`进行另一个示例。为此，转到浏览器，输入`localhost:3001/transaction/`到地址栏。在这之后，向端点添加一个随机的哈希值。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8d6c1399-a364-4f23-a5bf-20e7af95cc1c.png)

1.  运行此端点时，您将得到值为 null 的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/e34a4032-d60b-4bd7-98e7-7bf9ea0e20c0.png)

在前面的截图中返回的空值告诉我们，这个`transactionId`在区块链中不存在。

从测试中，我们可以得出结论，`/transaction/:transactionId`端点和`getTransaction`方法都正常工作。

# 构建`getAddressData`方法

我们将在区块链原型上构建一个名为`getAddressData`的新方法，并在`/address/:address`端点内部使用这个方法，以获取我们正在搜索的特定地址的数据：

1.  让我们在`blockchain.js`文件中构建这个新方法。在`getTransaction`方法之后，定义`getAddressData`方法如下：

```js
Blockchain.prototype.getAddressData = function(address) {

});
```

1.  现在，在这个方法内部，我们要做的第一件事是获取与该地址相关的所有交易，并将它们放入一个单一的数组中。让我们现在定义这个数组：

```js
Blockchain.prototype.getAddressData = function(address) {
       const addressTransactions = [];
});
```

1.  然后，我们要循环遍历区块链中的所有交易。如果任何这些区块中的交易的接收者或发送者是我们正在搜索的地址，那么我们要将所有这些交易添加到`addressTransactions`数组中。让我们定义这个条件如下。第一步是循环遍历区块链上的所有区块：

```js
Blockchain.prototype.getAddressData = function(address) {
       const addressTransactions = [];
       this.chain.forEach(block => {

 }); 
});
```

1.  现在，为了访问区块链中的交易，我们需要循环遍历每个区块上存在的所有交易。因此，在`forEach`循环内部，我们将不得不定义另一个`forEach`循环，如下所示：

```js
Blockchain.prototype.getAddressData = function(address) {
       const addressTransactions = [];
       this.chain.forEach(block => {
               block.transactions.forEach(transaction => {

 });
       }); 
});
```

1.  现在，在我们刚刚定义的`forEach`循环内部，我们可以访问区块链上的每一笔交易。我们只是想测试每笔交易，看看发送者或接收者地址是否与我们正在搜索的地址匹配：

```js
Blockchain.prototype.getAddressData = function(address) {
       const addressTransactions = [];
       this.chain.forEach(block => {
              block.transactions.forEach(transaction => {
                       if(transaction.sender === address ||
 transaction.recipient === address) {
 addressTransactions.push(transaction);
 }
               });
       }); 
});
```

在代码的这一点上，我们正在循环遍历我们区块链中的所有交易。如果我们遇到一个发送者地址或接收者地址等于我们正在寻找的地址的交易，那么我们将该交易推送到`addressTransactions`数组中。因此，在两个`forEach`循环都完成后，我们将得到一个包含与我们正在搜索的地址相关的所有交易的数组。

# 了解余额

接下来，我们要做的是循环遍历`addressTransactions`数组，以确定我们正在搜索的地址的余额。为了知道余额：

1.  让我们首先定义一个名为`balance`的变量：

```js
let balance = 0;
```

1.  接下来，我们要循环遍历`addressTransactions`数组中的所有交易。我们将使用`forEach`循环来做到这一点，如下所示：

```js
let balance = 0;
addressTransactions.forEach(transaction => { 

});
```

1.  在循环中，使用`if`和`else-if`语句提到条件，如下所示：

```js
let balance = 0;
addressTransactions.forEach(transaction => { 
       if (transaction.recipient === address) balance += transaction.amount;
        else if (transaction.sender === address) balance -= transaction.amount; 
}); 
```

1.  最后，在`forEach`循环结束时，我们要返回一个具有`addressTransactions`属性的对象，该属性与我们的`addressTransactions`数组匹配，并且`addressBalance`也是如此：

```js
let balance = 0;
addressTransactions.forEach(transaction => { 
       if (transaction.recipient === address) balance += transaction.amount;
        else if (transaction.sender === address) balance -= transaction.amount; 
}); 
return {
 addressTransactions: addressTransactions,
 addressBalance: balance
};
```

有了这个，我们就完成了`getAddressData`方法的构建。

# 开发/address/:address 端点

现在，让我们构建`/address/:address`端点，并在此端点内部使用`getAddressData`方法。`/address/:address`端点将与`/block/:blockHash`和`/transaction/:transactionId`端点非常相似，因此你不应该觉得太具有挑战性：

1.  在端点内部，我们要做的第一件事是将地址存储在一个变量中：

```js
app.get('/address/:address', function(req, res) {
       const address = req.params.address;
});
```

1.  我们要做的下一件事是使用`getAddressData`方法获取给定地址的所有数据。为了做到这一点，我们将在端点中添加以下突出显示的代码：

```js
app.get('/address/:address', function(req, res) {
       const address = req.params.address;
       bitcoin.getAddressData(address);
});
```

1.  通过这个方法，我们得到一个返回给我们的对象，其中包含`addressTransactions`和`addressBalance`。我们要将这些数据存储在一个变量中，如下所示：

```js
app.get('/address/:address', function(req, res) {
       const address = req.params.address;
       const addressData = bitcoin.getAddressData(address);
});
```

1.  最后，我们要返回包含这些数据的响应，如下所示：

```js
app.get('/address/:address', function(req, res) {
       const address = req.params.address;
       const addressData = bitcoin.getAddressData(address);
       res.json({
 addressData: addressData
 }); 

});
```

这就是我们构建`/address/:address`端点的方式。现在，让我们测试这个端点，以确保它能正常工作。

# 测试/address/:address 端点

为了测试端点，我们需要向区块链添加一些交易数据，让我们按照以下步骤来做：

1.  转到浏览器，探索`localhost:3001`上存在的区块链。你会发现这里只有一个区块。所以，让我们向其中添加更多的交易数据和区块。

1.  要做到这一点，转到 Postman，并将交易数据发送到`localhost:3001/transaction/broadcast`。在创建这些交易时，我们要确保跟踪一个特定的地址，以便在测试`/address/:address`端点时进行检查。为了跟踪这个特定的地址，让我们将一个地址的前三个字母改为 JEN。

1.  让我们创建第一笔交易。将`"amount":`值设置为`100`，并在此交易的发送者地址中添加`JEN`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/fccee6a3-b60d-4ba7-bcce-a543fd7b824e.png)

1.  然后，点击发送，将交易发送到节点`3001`。然后，按照类似的步骤，为`amount: 200`进行另一笔交易，这次将`JEN`添加到接收者的地址，并将发送者的地址保持为随机哈希值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c226b9dc-091b-4f5f-bc1f-eff848a816ab.png)

1.  现在，挖掘一个区块，将这些交易添加到区块链中。转到`localhost:3001/mine`，并按照以下方式在链中挖掘一个新的区块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/5b076c60-a2cc-4e30-9e60-22294cbc42a6.png)

同样地，你可以通过改变金额值和交换发送者和接收者的地址来进行更多的交易，其中地址中包含`JEN`。一旦创建了一些交易，就挖掘一个区块，将这些新交易添加到区块链中。然后，再次创建新的交易，并通过交换发送者和接收者的地址给它们不同的金额。再次挖掘一个新的区块，将交易添加到区块链中。

然后，通过访问`localhost:3001/blockchain`来探索整个区块链，其中包括我们添加的新交易和区块。你将看到一堆区块和区块链内的交易。

现在，为了测试`/address/:address`端点，让我们按照以下步骤进行：

1.  转到浏览器，在新标签页中输入`localhost:3001/address/`端点。

1.  然后，从我们刚刚添加到区块链中的交易中复制一个地址，并将其粘贴到端点中。参考下面的截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8cd99846-c3d7-4fc7-99fa-736b300ea724.png)

1.  现在，当我们运行这个端点时，我们应该看到与该特定地址相关的所有交易，以及该特定地址的比特币余额。看一下下面的截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/884fb442-2cc3-4913-8484-5ed4953f35d9.png)

在上面的截图中，我们得到了`addressData`属性的返回，其中包括`addressTransactions`数组和`addressBalance`属性。`addressTransactions`数组包括与我们在端点中提到的地址相关的所有交易。此外，`addressBalance`属性包括我们在端点中提到的地址的比特币余额：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/7f480b2b-6a5b-4407-a9c2-873c926051a2.png)

1.  接下来，你可以尝试通过复制挖矿奖励交易的接收者地址，并将其粘贴到`/address/:address`端点中，来检查节点地址的余额，就像我们在上一个例子中所做的那样。

1.  运行这个端点后，你将看到挖矿奖励交易的余额。尝试实现许多其他类似的例子，以更清楚地了解`/address/:address`端点的工作原理。

1.  另一个你可以尝试实现的例子是传递一个在区块链中不存在的地址。你将会得到以下返回的响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/d67a48d1-03c0-431a-8ef4-11eb567a95ec.png)

从前面的截图中，我们可以观察到`addressTransactions`数组为空，因为与我们输入的不存在的地址相关联的交易不存在。此外，不存在地址的`addressBalance`值为`0`。因此，我们可以从测试中得出结论，即`/address/:address`端点的工作方式正如它应该。

# 添加区块浏览器文件

让我们了解如何设置区块浏览器前端。区块浏览器将是一个用户界面，我们可以通过浏览器与区块链进行交互。为了构建这个用户界面并使其功能正常，我们需要使用 HTML、CSS 和 JavaScript。

现在，您不必自己构建所有的前端，您可以在以下链接找到一个完整的预构建前端：[`github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/block-explorer/index.html`](https://github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/block-explorer/index.html)。我们在本节中没有构建整个前端，因为这不是本书的重点。

要构建前端，您只需复制提供的链接中的文件并将其添加到项目的文件结构中。现在，转到`dev`文件夹并在其中创建一个名为`block-explorer`的新文件夹。在这个`block-explorer`文件夹内，创建一个名为`index.html`的文件，然后将提供的前端代码粘贴到其中并保存文件。您将在下一节中快速了解这个前端代码包含什么以及代码在哪里起作用。

# 构建`/block-explorer`端点

让我们构建一个端点，用于检索`block-explorer`文件：

1.  转到`dev/networkNode.js`文件，在这里，创建一个新的端点，将向我们发送这个文件。定义端点如下：

```js
app.get('/block-explorer', function(req, res) {

});
```

1.  现在，在这个端点内，我们想做的就是将`index.html`文件发送回给调用这个端点的人：

```js
app.get('/block-explorer', function(req, res) {
    res.sendFile('./block-explorer/index.html', { root: __dirname });
});
```

在前面的部分中，您可能已经注意到我们通常使用`res.json`，这是发送 JSON 数据的一种方式。然而，在这个端点中，我们想要发送整个文件，所以我们将使用`res.sendFile`方法。请注意，在前面的代码中，我们使用了`{ root: __dirname }`。这段代码表示我们应该查看项目存储的目录，并在其中查找具有`/block-explorer/index.html`路径的文件。这就是为什么我们将此选项作为第二个参数添加到端点中的原因，也是我们如何构建一个发送`index.html`文件的端点。

1.  接下来，保存`networkNode.js`文件，并通过在浏览器中访问`localhost:3001/block-explorer`来验证这个端点是否有效。然后，您将看到区块浏览器的前端，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/45b96e5c-3143-4922-be7d-573ae6a1cc22.png)

您在这个前端中看到的所有内容都包含在我们刚刚创建的`index.html`文件中。

# 区块浏览器文件说明

在本节中，我们将简单地浏览一下我们在上一节中创建的`index.html`文件。我们将这样做是为了更好地理解发生了什么。所以，让我们开始吧。

在`index.html`文件中，我们有所有的 HTML 和 JavaScript 代码，为区块浏览器提供必要的功能。这段代码还允许我们访问 API，最后，我们只是有一些 CSS 和样式，使一切在浏览器中看起来很好。

代码首先导入了一些库，比如`angular.js`，用于访问 API，还有 jQuery、Bootstrap 和一些 Bootstrap 样式，使一切功能正常且美观：

```js
<head>
  <title>Block Explorer</title>
  <script src="img/angular.min.js"></script>
  <script src="img/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>
  <script src="img/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
  <link rel="stylesheet" type="text/css" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
```

接下来，我们有 HTML 模型的主体，其中包括区块浏览器的标题：

```js
<body ng-app="BlockExplorer">
  <div class="container" ng-controller="MainController">
    <div class="row">
      <div class="col-md-8 offset-md-2">
        <h1 id="page-title">Block Explorer</h1>
      </div>
    </div
```

然后，我们有一个文本输入表单：

```js
<div class="row">
      <div class="col-md-6 offset-md-3">
        <form ng-submit="search(searchValue)">
          <div class="form-group">
            <input type="text" class="form-control" ng-model="searchValue">
          </div>
```

接下来，我们有一个`select`输入，其中包含三个选项：`区块哈希`、`交易 ID`和`地址`：

```js
<div class="form-group">
        <select class="form-control" ng-model="searchType">
                <option value="block">Block Hash</option>
                <option value="transaction">Transaction ID</option>
                <option value="address">Address</option>
        </select>
</div>
```

要使用此页面，让我们在文本字段中输入块哈希、交易 ID 或地址，然后从下拉菜单中选择我们要查找的内容，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2174b88c-b631-43d0-b652-89344466b170.png)

最后，在 HTML 代码中，一旦我们从区块链中获得了一些数据，我们只需有一些表格来显示所有的数据。

此外，我们的`index.html`文件中还有一些 JavaScript 代码。在这个 JavaScript 代码中，我们使用 Angular 来调用我们的 API：

```js
 window.app = angular.module('BlockExplorer', []);
 app.controller('MainController', function($scope, $http) {
          $scope.block = null;
          $scope.transaction = null;
          $scope.addressData = null;
          $scope.initialSearchMade = false;
```

然后我们有一个方法，当我们选择“块哈希”选项时，我们会命中`/block/:blockHash`端点：

```js
$scope.fetchBlock = function(blockHash) {
        $http.get(`/block/${blockHash}`)
        .then(response => {
          $scope.block = response.data.block;
          $scope.transaction = null;
          $scope.addressData = null;
        });
      };
```

同样，我们还有`/transaction/:transactionId`端点的方法：

```js
$scope.fetchTransaction = function(transactionId) {
        $http.get(`/transaction/${transactionId}`)
        .then(response => {
          $scope.transaction = response.data.transaction;
          $scope.block = null;
          $scope.addressData = null;
        }); 
      };
```

我们还有`/address/:address`端点的方法：

```js
$scope.fetchAddressData = function(address) {
        $http.get(`/address/${address}`)
        .then(response => {
          $scope.addressData = response.data.addressData;
          if (!$scope.addressData.addressTransactions.length) $scope
            .addressData = null;
          $scope.block = null;
          $scope.transaction = null;
        }); 
      };
```

在接下来的 JavaScript 代码中，我们只有一点点更多的功能，然后在代码的最后有 CSS 样式。因此，这段代码包含在`index.html`文件中。如果您想深入了解，以获得更清晰的理解，可以随意这样做。您也可以根据自己的喜好进行自定义。

然后点击搜索，如果指定的数据存在于区块链中，将显示一个表格，其中将显示所有这些数据。如果我们的区块链上不存在数据，您将得到未找到数据的结果。这就是区块浏览器前端的工作原理。

到目前为止，我们已经构建了一个完整的区块浏览器前端，并且我们有区块浏览器的后端——我们刚刚创建的三个端点，以便搜索整个区块链。

在下一节中，我们将测试区块浏览器，以确保它完美地工作。

# 测试我们的区块浏览器

在这一部分，我们将测试区块浏览器，以确保其正常工作，并确保我们在上一章中创建的所有端点和方法也能正常工作。如果区块浏览器正常工作，那么我们已经知道整个区块链也在去中心化的区块链网络上正常运行，所以当我们进入本章的最后一部分时，一切都很顺利地结束了。因此，这是我们将要进行的最后一次测试。现在让我们按照以下步骤来测试区块浏览器：

1.  为了测试区块浏览器，我们应该确保我们有五个节点都在运行。

1.  接下来，转到浏览器，通过`localhost:3003/block-explorer`打开区块浏览器。实际上，您可以转到网络中任何一个节点上托管的区块浏览器，因为整个区块链是托管在整个网络上的。

1.  现在，为了测试区块浏览器，我们需要向区块链添加一些数据。要向区块链添加数据，我们只需创建大量交易并创建一些新的区块，类似于我们在前几节中所做的。您可以参考前几章，快速回顾如何向区块链添加交易和区块。

1.  在添加数据之后，我们现在可以测试区块浏览器。让我们首先通过搜索块哈希来获取一个块。让我们选择“块哈希”选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a465bd88-f866-497e-afcb-2f18883956ed.png)

1.  然后，从区块链中复制任何一个块的哈希值，并将其粘贴到区块浏览器中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8799bb9d-11df-4f03-b42f-792ae81be284.png)

1.  现在，点击搜索按钮。您应该看到与以下截图中类似的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/7a17bde2-ca74-4ef8-9c1d-229fcff582c5.png)

这基本上是区块浏览器的工作原理。我们输入我们正在寻找的哈希或数据片段，作为回报，我们得到该数据片段作为输出。从前面的屏幕截图中，我们可以观察到，我们输入到区块浏览器的哈希值返回了索引为`4`的区块。我们还得到了与该区块相关的所有细节。此外，您可能已经注意到，对于此搜索，我们正在命中`/block/:blockHash`端点。

1.  接下来，通过输入`transactionId`搜索交易。转到区块浏览器并选择交易 ID 选项。然后，转到区块链并从任何区块中复制一个`transactionId`值，并将其输入到区块浏览器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f116f514-a314-46df-87d6-2d0d85c2a27b.png)

1.  然后点击搜索按钮。您将看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8098b0c5-0ac5-4d8c-aa10-7e2d873883f9.png)

从前面的屏幕截图中，我们可以看到我们得到了与我们输入到区块浏览器的`transactionId`相关的所有交易细节。我们还得以观察到该特定`transactionId`的比特币余额为 400 比特币。

1.  最后，测试地址端点。要做到这一点，从区块浏览器中选择地址选项，然后输入任何一个区块中的发件人或收件人地址。然后点击搜索按钮。您应该在屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/495f512d-da51-4440-8836-d6983e0ae3e0.png)

从前面的屏幕截图中，我们可以看到该地址有 749.35 比特币的余额，并且我们可以看到与我们输入的地址相关的所有交易。

现在，对于这些搜索中的任何一个，如果我们输入一个不存在的数据片段，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/9badf319-0a93-47cf-9900-c18977e4e4ec.png)

这证明了区块浏览器的工作原理与应有的一样。

# 总结

在本章中，我们构建了一个令人惊叹的用户界面，用于探索本书中构建的区块链。我们首先定义了查询所需数据的必要端点。然后，我们构建了诸如`getBlock`、`getTransaction`和`getAddressData`之类的方法，以帮助端点查询数据。此外，我们开发了`/block/:blockHash`、`/transaction/:transactionId`和`/address/:address`端点。在做完这些之后，我们将区块浏览器的前端代码添加到我们的区块链目录中，然后测试了区块浏览器和我们开发的所有端点。

通过本章，我们已经到达了本书的结尾。到目前为止，我们已经构建了自己的区块链，并为其添加了所有必要的功能。除此之外，我们还建立了我们自己的去中心化网络，并建立了一个用于探索区块链的界面。

下一章将是对本书中所学内容的快速总结。然后，我们将探索我们已开发的区块链还可以做些什么。
