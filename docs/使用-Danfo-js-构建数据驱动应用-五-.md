# 使用 Danfo.js 构建数据驱动应用（五）

> 原文：[`zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F`](https://zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：TensorFlow.js 简介

在上一章中，你已经了解了**机器学习**（**ML**）的基础知识，并学习了一些理论基础，这些基础是构建和使用 ML 模型所必需的。

在本章中，我们将向你介绍 JavaScript 中一个高效且流行的 ML 库 TensorFlow.js。在本章结束时，你将知道如何安装和使用 TensorFlow.js，如何创建张量，如何使用 Core **应用程序编程接口**（**API**）对张量进行操作，以及如何使用 TensorFlow.js 的 Layer API 构建回归模型。

在本章中，我们将涵盖以下主题：

+   什么是 TensorFlow.js？

+   安装和使用 TensorFlow.js

+   张量和张量的基本操作

+   使用 TensorFlow.js 构建简单的回归模型

# 技术要求

在本章中，你应该具备以下工具或资源：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox。

+   在你的系统上安装了 Node.js

+   稳定的互联网连接，用于下载软件包和数据集

+   本章的代码可在 GitHub 上克隆并获取，网址为[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter10`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter10)

# 什么是 TensorFlow.js？

**TensorFlow.js**（**tfjs**）是一个 JavaScript 库，用于在浏览器或 Node.js 中创建、训练和部署 ML 模型。它是由 Google 的 Nikhil Thorat 和 Daniel Smilkov 创建的，最初被称为 Deeplearn.js，在 2018 年并入 TensorFlow 团队并更名为 TensorFlow.js。

TensorFlow.js 提供了两个主要层，如下所述：

+   **CoreAPI**：这是直接处理张量的低级 API——TensorFlow.js 的核心数据结构。

+   **LayerAPI**：这是建立在 CoreAPI 层之上的高级层，用于轻松构建 ML 模型。

在后面的章节中，*张量和张量的基本操作*和*使用 TensorFlow.js 构建简单的回归模型*，你将学到更多关于 CoreAPI 和 LayerAPI 层的细节。

使用 TensorFlow.js，你可以做到以下几点：

+   执行硬件加速的数学运算

+   为浏览器或 Node.js 开发 ML 模型

+   使用**迁移学习**（**TL**）重新训练现有的 ML 模型

+   重用使用 Python 训练的现有 ML 模型

在本章中，我们将介绍执行硬件加速的数学运算以及使用 TensorFlow.js 开发 ML 模型。如果你想了解最后两种用例——重新训练和重用 ML 模型——那么官方的 TensorFlow.js 文档([`www.tensorflow.org/js/guide`](https://www.tensorflow.org/js/guide))是一个很好的起点。

现在我们已经介绍完了，接下来的章节中，我们将向你展示如何在浏览器和 Node.js 环境中安装和使用 TensorFlow.js。

# 安装和使用 TensorFlow.js

正如我们之前提到的，TensorFlow.js 可以在浏览器和 Node.js 环境中安装和运行。在接下来的段落中，我们将向你展示如何实现这一点，从浏览器开始。

## 在浏览器中设置 TensorFlow.js

在浏览器中安装 TensorFlow.js 有两种方式。这里进行了概述：

+   通过脚本标签

+   使用诸如**Node Package Manager**（**npm**）或**Yarn**之类的包管理器

### 通过脚本标签安装

通过`script`标签安装 TensorFlow.js 很容易。只需将`script`标签放在你的**超文本标记语言**（**HTML**）文件的头文件中，如下面的代码片段所示：

```js
<script src="img/tf.min.js"></script>
```

要确认 TensorFlow.js 已安装，打开浏览器中的 HTML 文件，并检查网络标签。你应该看到名称为`tf.min.js`和状态码为`200`，如下截图所示：

![图 10.1 - 网络标签显示了 tfjs 成功安装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_01.jpg)

图 10.1 - 网络标签显示了 tfjs 成功安装

您可以在 HTML 文件的 body 中添加一个简单的脚本来确认成功安装`tfjs`。在 HTML 文件的`script`部分中，添加以下代码：

```js
...
<script>
         tf.ready().then(()=>{
            console.log("Tensorflow.js loaded successfully!");
        })
 </script>
...
```

上面的代码片段将在浏览器控制台中记录文本`Tensorflow.js loaded` `successfully!`，一旦 TensorFlow.js 加载并准备好在页面上使用。要查看输出，请在浏览器中打开 HTML 文件并检查控制台输出。您应该会看到一个输出结果，如下面的屏幕截图所示：

![图 10.2 - add 操作的张量输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_02.jpg)

图 10.2 - add 操作的张量输出

接下来，让我们看看如何通过软件包管理器安装`tfjs`。

### 通过软件包管理器安装

您可以通过`npm`或`yarn`等软件包管理器安装`tfjs`。当您需要在客户端项目（如 React 和 Vue 项目）中使用`tfjs`时，这是非常有用的。

要使用`npm`安装，请在**命令行界面**（**CLI**）中运行以下命令：

```js
npm install @tensorflow/tfjs
```

要使用`yarn`安装，也可以在 CLI 中运行以下命令：

```js
yarn add @tensorflow/tfjs
```

注意

在通过 CLI 成功安装软件包之前，您必须在系统中安装`npm`或`yarn`之一，最好是全局安装。如果您已经安装了 Node.js，那么您已经有了`npm`。要安装`yarn`，您可以按照这里的步骤进行操作：[`classic.yarnpkg.com/en/docs/install/#mac-stable`](https://classic.yarnpkg.com/en/docs/install/#mac-stable)。

安装成功后，您可以导入并使用`tfjs`，如下面的代码片段所示：

```js
import * as tf from '@tensorflow/tfjs';
const x = tf.tensor2d([1, 2, 3, 4], [2, 2]);
const y = tf.tensor2d([1, 3, 5, 7], [2, 2]);
const sum = x.add(y)
 sum.print()
```

运行上面的代码片段将在控制台中产生以下输出：

![图 10.3 - 使用软件包管理器安装 tfjs 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_03.jpg)

图 10.3 - 使用软件包管理器安装 tfjs 的输出

通过按照上面的代码块中的步骤，您应该能够在浏览器或客户端框架中安装和使用`tfjs`。在下一节中，我们将向您展示如何在 Node.js 环境中安装`tfjs`。

## 在 Node.js 中安装 TensorFlow.js

在 Node.js 中安装`tfjs`非常简单，但首先确保您的系统上已安装了 Node.js、`npm`或`yarn`。

Node.js 中的 TensorFlow.js 有三个选项，安装的选择将取决于您的系统规格。在接下来的子章节中，我们将向您展示这三个选项。

### 使用本机 C++绑定安装 TensorFlow.js

`@tensorflow/tfjs-node`（`www.npmjs.com/package/@tensorflow/tfjs-node`）版本的`tfjs`直接连接到 TensorFlow 的本机 C++绑定。这使它快速，并且使其与 TensorFlow 的 Python 版本具有接近的性能。这意味着`tfjs-node`和`tf.keras`在内部使用相同的 C++绑定。 

要安装`tfjs-node`，只需通过 CLI 运行以下命令：

```js
npm install @tensorflow/tfjs-node
```

或者，如果使用`yarn`，也可以通过 CLI 运行以下命令：

```js
yarn add @tensorflow/tfjs-node
```

### 安装支持 GPU 的 TensorFlow.js

`@tensorflow/tfjs-node-gpu`版本的`tfjs`支持在`tfjs-node-gpu`上运行操作，通常比`tfjs-node`快，因为操作可以很容易地进行矢量化。

要安装`tfjs-node-gpu`，只需通过 CLI 运行以下命令：

```js
npm install @tensorflow/tfjs-node-gpu
```

或者，如果您使用`yarn`，也可以通过 CLI 运行以下命令：

```js
yarn add @tensorflow/tfjs-node-gpu
```

### 安装普通的 TensorFlow.js

`@tensorflow/tfjs`版本是`tfjs`的纯 JavaScript 版本。在性能方面它是最慢的，应该很少使用。

要安装此版本，只需通过 CLI 运行以下命令：

```js
npm install @tensorflow/tfjs
```

或者，如果您使用`yarn`，也可以通过 CLI 运行以下命令：

```js
yarn add @tensorflow/tfjs
```

如果您按照上述步骤操作，那么您应该至少安装了`tfjs`的一个版本。您可以使用以下代码示例测试安装是否成功：

```js
const tf = require('@tensorflow/tfjs-node')
// const tf = require('@tensorflow/tfjs-node-gpu') GPU version
// const tf = require('@tensorflow/tfjs') Pure JS version
const xs = tf.randomNormal([100, 10])
const ys = tf.randomNormal([100, 1])
const sum = xs.add(ys)
const xsSum = xs.sum()
const xsMean = xs.mean()

console.log("Sum of xs and ys")
sum.print()
console.log("Sum of xs")
xsSum.print()
console.log("Mean of xs")
xsMean.print()
```

注意

当我们想要查看底层数据时，我们在张量上调用`print()`函数。如果我们使用默认的`console.log`，我们将得到`Tensor`对象。

运行前面的代码应该在控制台中输出以下内容：

![图 10.4 - 在 Node.js 中测试 tfjs 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_04.jpg)

图 10.4 - 在 Node.js 中测试 tfjs 的输出

现在您已经成功在项目中安装了`tfjs`，在下一节中，我们将向您介绍`tfjs`的核心数据结构——张量。

# 张量和张量的基本操作

张量是`tfjs`中的基本数据结构。您可以将张量视为向量、矩阵或高维数组的泛化。我们在*什么是 TensorFlow.js？*部分介绍的**CoreAPI**公开了不同的函数，用于创建和处理张量。

以下屏幕截图显示了标量、向量和矩阵与张量之间的简单比较：

![图 10.5 - 简单的 n 维数组与张量的比较](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_05.jpg)

图 10.5 - 简单的 n 维数组与张量的比较

提示

矩阵是一个`m x n`数字的网格，其中`m`表示行数，`n`表示列数。矩阵可以是一维或多维的，形状相同的矩阵支持彼此的直接数学运算。

另一方面，向量是一个一维矩阵，形状为（1，1）；也就是说，它有一行和一列，例如，[2, 3]，[3, 1, 4]。

我们之前提到过，张量更像是一个广义的矩阵，它扩展了矩阵的概念。张量可以通过它们的秩来描述。秩类似于形状的概念，但是用一个数字表示，而不是形状。在下面的列表中，我们看到了不同类型的张量秩及其示例：

+   秩为 0 的张量是标量，例如，1、20 或 100。

+   秩为 1 的张量是向量，例如，[1, 20]或[20, 100, 23.6]。

+   秩为 2 的张量是矩阵，例如，[[1, 3, 6], [2.3, 5, 7]]。

请注意，我们可以有秩为 4 或更高的张量，这些被称为更高维度的张量，可能难以可视化。请参见下面的屏幕截图，以更好地理解张量：

![图 10.6 - 不同秩的张量比较](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_06.jpg)

图 10.6 - 不同秩的张量比较

除了秩，张量还具有其他属性，如`dtype`、`data`、`axis`和`shape`。这些在这里更详细地描述：

+   `dtype`属性（数据类型）是张量持有的数据类型，例如，秩为 1 的张量具有以下数据[2.5, 3.8]，其 dtype 为`float32`。默认情况下，数值张量的 dtype 为`float32`，但可以在创建过程中更改。TensorFlow.js 支持`float32`、`int32`、`bool`、`complex64`和`string`数据类型。

+   `data`属性是张量的内容。这通常存储为数组。

+   `axis`属性是张量的特定维度，例如，*m x n*张量具有*m*或*n*的轴。轴可用于指定在哪个维度上执行操作。

+   `shape`属性是张量的维度。将形状视为张量每个轴上的元素数量。

现在您对张量是什么有了基本的了解，在下一小节中，我们将向您展示如何创建张量并对其进行一些基本操作。

## 创建张量

张量可以使用`tf.tensor()`方法创建，如下面的代码片段所示：

```js
const tf = require('@tensorflow/tfjs-node')

const tvector = tf.tensor([1, 2, 3, 4]);
console.log(tvector)
//output
Tensor {
  kept: false,
  isDisposedInternal: false,
  shape: [ 4 ],
  dtype: 'float32',
  size: 4,
  strides: [],
  dataId: {},
  id: 0,
  rankType: '1'
}
```

在前面的代码片段中，我们将一个平坦数组（向量）传递给`tf.tensor()`方法，以创建一个`tfjs`张量。创建后，我们现在可以访问不同的属性和函数，用于操作或转换张量。

其中一个属性是`shape`属性，我们可以按照下面的代码片段中所示进行调用：

```js
console.log('shape:', tvector.shape);
//outputs: shape: [ 4 ]
```

请注意，当您使用`console.log`记录张量时，您会得到一个张量对象。如果您需要查看底层张量数组，可以在张量上调用`print()`函数，如下面的代码片段所示：

```js
tvector.print();
//outputs
Tensor
    [1, 2, 3, 4]
```

如果您需要访问张量的基础数据，可以调用`array()`或`arraySync()`方法。两者之间的区别在于，`array()`是异步运行的，并返回一个解析为基础数组的 promise，而`arraySync()`是同步运行的。您可以在这里看到一个示例：

```js
const tvectorArray = tvector.array()
const tvectorArraySync = tvector.arraySync()
console.log(tvectorArray)
console.log(tvectorArraySync)
//outputs
Promise { <pending> }
[ 1, 2, 3, 4 ]
```

您还可以通过指定`shape`参数来创建张量。例如，在下面的代码片段中，我们从一个平坦数组创建一个 2 x 2（**二维**（**2D**））张量：

```js
const ts = tf.tensor([1, 2, 3, 4], [2, 2]);
console.log('shape:', ts.shape);
ts.print();
//outputs
shape: [ 2, 2 ]
Tensor
    [[1, 2],
     [3, 4]]
```

或者，我们可以创建一个 1 x 4（**一维**（**1D**））张量，如下面的代码片段所示：

```js
const ts = tf.tensor([1, 2, 3, 4], [1, 4]);
console.log('shape:', ts.shape);
ts.print();
//outputs
shape: [ 1, 4 ]
Tensor
     [[1, 2, 3, 4],]
```

但请注意，形状必须匹配元素的数量，例如，您不能从具有四个元素的平坦数组创建一个`2 x 5`维的张量。以下代码将引发形状错误：

```js
const ts = tf.tensor([1, 2, 3, 4], [2, 5]);
```

输出如下所示：

![图 10.7 – 形状不匹配引发的错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_07.jpg)

图 10.7 – 形状不匹配引发的错误

`Tfjs`明确提供了用于创建 1D、2D、`shape`参数的函数。您可以在官方`tfjs` API 中阅读更多关于创建张量的信息：[`js.tensorflow.org/api/latest/#Tensors-Creation`](https://js.tensorflow.org/api/latest/#Tensors-Creation)。

默认情况下，张量具有`float32`的`dtype`属性，因此您创建的每个张量都将具有`float32`的`dtype`。如果这不是所需的`dtype`，您可以在张量创建时指定类型，就像我们在以下代码片段中演示的那样：

```js
const tsInt = tf.tensor([1, 2, 3, 4], [1, 4], 'int32');
console.log('dtype:', tsInt.dtype);
//outputs
dtype: int32
```

现在您知道如何创建张量，我们将继续对张量进行操作。

## 对张量进行操作

正如我们之前所说，张量以网格形式存储数据，并允许进行许多操作来操作或转换这些数据。`tfjs`提供了许多用于线性代数和机器学习的运算符。

`tfjs`中的操作被分成不同的部分。以下是一些常见操作的解释：

+   `add()`用于张量的加法，`sub()`用于张量的减法，`mul()`用于张量的乘法，`div()`用于张量的除法。在这里可以看到带有示例的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Arithmetic`](https://js.tensorflow.org/api/3.7.0/#Operations-Arithmetic)。

+   `cos()`用于计算张量的余弦，`sin()`用于计算张量的正弦，`exp()`用于计算张量的指数，`log()`用于计算张量的自然对数。在这里可以看到带有示例的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Basic%20math`](https://js.tensorflow.org/api/3.7.0/#Operations-Basic%20math)。

+   **矩阵**：这些运算符用于矩阵运算，如点积、范数或转置。您可以在这里看到支持的运算符的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Matrices`](https://js.tensorflow.org/api/3.7.0/#Operations-Matrices)。

+   `conv1d`，用于计算输入`x`的 1D 卷积，以及`maxpool3D`，用于计算 3D 最大池化操作。在这里可以看到完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Convolution`](https://js.tensorflow.org/api/3.7.0/#Operations-Convolution)。

+   `min`、`max`、`sum`、`mean`、`argMax`和`argMin`。您可以在这里看到带有示例的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Reduction`](https://js.tensorflow.org/api/3.7.0/#Operations-Reduction)。

+   `equal`、`greater`、`greaterEqual`和`less`。您可以在这里看到带有示例的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations-Logical`](https://js.tensorflow.org/api/3.7.0/#Operations-Logical)。

您可以在官方 API 中看到支持的操作的完整列表：[`js.tensorflow.org/api/3.7.0/#Operations`](https://js.tensorflow.org/api/3.7.0/#Operations)。

现在您对可用的张量运算符有了基本的了解，我们将展示一些代码示例。

### 对张量应用算术运算

我们可以通过直接在第一个张量上调用`add()`方法并将第二个张量作为参数传递来添加两个张量，如下面的代码片段所示：

```js
const tf = require('@tensorflow/tfjs-node')
const a = tf.tensor1d([1, 2, 3, 4]);
const b = tf.tensor1d([10, 20, 30, 40]);
a.add(b).print();
//outputs
Tensor
    [11, 22, 33, 44]
```

请注意，您还可以通过在`tf`对象上调用运算符来直接添加或应用任何运算符，如下面的代码片段所示：

```js
const tf = require('@tensorflow/tfjs-node')
const a = tf.tensor1d([1, 2, 3, 4]);
const b = tf.tensor1d([10, 20, 30, 40]);
const sum = tf.add(a, b)
sum.print()
//outputs
Tensor
    [11, 22, 33, 44]
```

使用这些知识，您可以执行其他算术运算，如减法、乘法、除法和幂运算，如下面的代码片段所示：

```js
const a = tf.tensor1d([1, 2, 3, 4]);
const b = tf.tensor1d([10, 20, 30, 40]);

const tfsum = tf.add(a, b)
const tfsub = tf.sub(b, a)
const tfdiv = tf.div(b, a)
const tfpow = tf.pow(b, a)
const tfmax = tf.maximum(a, b)

tfsum.print()
tfsub.print()
tfdiv.print()
tfpow.print()
tfmax.print()
//outputs
Tensor
    [11, 22, 33, 44]
Tensor
    [9, 18, 27, 36]
Tensor
    [10, 10, 10, 10]
Tensor
    [10, 400, 27000, 2560000]
Tensor
    [10, 20, 30, 40]
```

值得一提的是，传递给运算符的张量的顺序很重要，因为顺序的改变会导致结果不同。例如，如果我们将前面的`div`操作的顺序从`const tfsub = tf.sub(b, a)`改为`const tfsub = tf.sub(a, b)`，那么我们会得到一个负结果，如下面的输出所示：

```js
Tensor
    [-9, -18, -27, -36]
```

请注意，涉及两个张量的所有操作只有在两个张量具有相同形状时才能工作。例如，以下操作将引发无效形状错误：

```js
const a = tf.tensor1d([1, 2, 3, 4]);
const b = tf.tensor1d([10, 20, 30, 40, 50]);
const tfsum = tf.add(a, b)
```

![图 10.8–在具有不同形状的张量上执行操作时出现无效形状错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_08.jpg)

图 10.8–在具有不同形状的张量上执行操作时出现无效形状错误

在下一小节中，我们将看一些关于张量的基本数学运算的例子。

### 在张量上应用基本数学运算

根据前一小节的示例格式，*在张量上应用算术运算*，我们给出了一些在张量上计算数学运算的示例，如下所示：

```js
const tf = require('@tensorflow/tfjs-node')

const x = tf.tensor1d([-1, 2, -3, 4]);
x.abs().print();  // Computes the absolute values of the tensor
x.cos().print(); // Computes the cosine of the tensor
x.exp().print(); // Computes the exponential of the tensor
x.log().print(); // Computes the natural logarithm  of the tensor
x.square().print(); // Computes the sqaure of the tensor
```

输出如下所示：

```js
Tensor
    [1, 2, 3, 4]
Tensor
    [0.5403023, -0.4161468, -0.9899925, -0.6536436]
Tensor
    [0.3678795, 7.3890562, 0.0497871, 54.5981522]
Tensor
    [NaN, 0.6931472, NaN, 1.3862944]
Tensor
    [1, 4, 9, 16]
```

正如我们之前提到的，您可以直接从`tf`对象调用运算符，例如，`x.cos()`变成了`tf.cos(x)`。

### 在张量上应用减少操作

我们还可以对张量应用诸如`mean`、`min`、`max`、`argMin`和`argMax`之类的减少操作。以下是一些`mean`、`min`、`max`、`argMin`和`argMax`的例子：

```js
const x = tf.tensor1d([1, 2, 3]);
x.mean().print();  // or tf.mean(x)  Returns the mean value of the tensor
x.min().print();  // or tf.min(x) Returns the smallest value in the tensor
x.max().print();  // or tf.max(x) Returns the largest value in the tensor
x.argMax().print();  // or tf.argMax(x) Returns the index of the largest value
x.argMin().print();  // or tf.argMin(x) Returns the index of the smallest value
```

输出如下所示：

```js
Tensor 2
Tensor 1
Tensor 3
Tensor 2
Tensor 0
```

掌握了 ML、张量和可以在张量上执行的操作的基本知识，现在您已经准备好构建一个简单的 ML 模型了。在本章的下一节中，我们将总结您在本节中学到的所有内容。

# 使用 TensorFlow.js 构建一个简单的回归模型

在上一章[*第九章*]（B17076_09_ePub_RK.xhtml#_idTextAnchor166），*机器学习基础*中，您已经了解了 ML 的基础知识，特别是回归和分类模型的理论方面。在本节中，我们将向您展示如何使用`tfjs` **LayerAPI**创建和训练回归模型。具体来说，在本节结束时，您将拥有一个可以从超市数据中预测销售价格的回归模型。

## 在本地设置您的环境

在构建回归模型之前，您必须在本地设置您的环境。在本节中，我们将在 Node.js 环境中工作。这意味着我们将使用 TensorFlow.js 和 Danfo.js 的`node`版本。

按照这里的步骤设置您的环境：

1.  在新的工作目录中，为您的项目创建一个文件夹。我们将创建一个名为`sales_predictor`的文件夹，如下面的代码片段所示：

```js
mkdir sales_predictor
cd sales_predictor
```

1.  接下来，在文件夹目录中打开终端，并通过运行以下命令初始化一个新的`npm`项目：

```js
npm init
```

1.  接下来，按照以下步骤安装`Danfo.js`节点包：

```js
yarn add danfojs-node
or if using npm
npm install danfojs-node
```

1.  还可以从终端创建一个`src`文件夹，并添加`train.js`，`model.js`和`data` `_proc.js`文件。您可以通过代码编辑器手动创建这些文件夹/文件，也可以通过在终端中运行以下命令来创建：

```js
data_proc.js, and model.js) in the src folder. These files will contain code for processing data, creating a tfjs model, and model training, respectively.
```

现在您已经设置好了项目和文件，我们将在下一节中继续进行数据检索和处理步骤。

## 检索和处理训练数据集

我们将用于模型训练的数据集称为*BigMart 销售数据集*（[`www.kaggle.com/devashish0507/big-mart-sales-prediction`](https://www.kaggle.com/devashish0507/big-mart-sales-prediction)）。它作为一个公共数据集在 Kaggle 上可用，这是一个流行的数据科学竞赛平台。

您可以直接从本章的代码库中下载数据集：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter10/sales_predictor/src/dataset/Train.csv`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter10/sales_predictor/src/dataset/Train.csv)。成功下载后，在您的项目目录中创建一个名为`dataset`的文件夹，并将数据集复制到其中。

为了确认一切都正常，您的项目`src`文件夹应该具有以下文件结构：

```js
|-data-proc.js
|-dataset
|   └── Train.csv
|-model.js
|-train.js
```

与所有数据科学问题一样，通常会提供一个通用的问题陈述，以指导您解决的问题。就 BigMart 销售数据集而言，问题陈述如下：

*BigMart 已经收集了 2013 年在不同城市的 10 家商店中 1,559 种产品的销售数据。此外，每种产品和商店的某些属性已经被定义。目标是建立一个预测模型，找出每种产品在特定商店的销售情况。*

从前面的问题陈述中，您将注意到构建此模型的目的是帮助 BigMart 有效预测每种产品在特定商店的销售情况。现在，这里的销售价格意味着一个连续的值，因此，我们有一个回归问题。

现在您已经可以访问数据并理解了问题陈述，您将使用`Danfo.js`加载数据集并进行一些数据处理和清理。

注意

我们在代码库中提供了一个单独的**Danfo Notebook**（**Dnotebook**）文件：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter10/sales_predictor/src/bigmart%20sales%20notebook.json`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter10/sales_predictor/src/bigmart%20sales%20notebook.json)。在笔记本中，我们对销售数据集进行了一些数据探索和分析，其中大部分将帮助我们进行以下处理步骤。

在您的代码编辑器中打开`data_proc.js`文件，按照这里给出的步骤处理 BigMart 销售数据集：

1.  首先，我们将导入`danfojs-node`，如下所示：

```js
const dfd = require("danfojs-node")
```

1.  然后，我们创建一个名为`processData`的函数，该函数接受数据集路径，如下所示：

```js
async function processData(trainDataPath) {
    //… process code goes here
}
```

1.  接下来，在`processData`函数的主体中，我们使用`read_csv`函数加载数据集并打印标题，如下所示：

```js
const salesDf = await dfd.read_csv(trainDataPath)
salesDf.head().print()
```

1.  为了确保数据加载正常工作，您可以将数据集的路径传递给`processData`函数，如下面的代码片段所示：

```js
processData("./dataset/train.csv")
```

1.  在您的终端中，使用以下命令运行`data_proc.js`文件：

```js
node data_proc.js
```

这将输出以下内容：

![图 10.9 - 显示 BigMart 销售数据集的头部值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_09.jpg)

图 10.9 - 显示 BigMart 销售数据集的头部值

1.  从 Dnotebook 文件的分析中，我们注意到`Item_Weight`和`Outlet_Sales`两列存在缺失值。在下面的代码片段中，我们将使用均值和众数分别填充这些缺失值：

```js
...   
 salesDf.fillna({
        columns: ["Item_Weight", "Outlet_Size"],
        values: [salesDf['Item_Weight'].mean(), "Medium"],
        inplace: true
    })
...
```

1.  正如我们注意到的，数据集是混合的分类（字符串）列和数值（`float32`和`int32`）列。这意味着我们必须在将它们传递给我们的模型之前，将所有分类列转换为数值形式。在下面的代码片段中，我们使用 Danfo.js 的`LabelEncoder`将每个分类列编码为数值列：

```js
...
     let encoder = new dfd.LabelEncoder()
     let catCols = salesDf.select_dtypes(includes = ['string']).column_names // get all categorical column names
     catCols.forEach(col => {
        encoder.fit(salesDf[col])
        enc_val = encoder.transform(salesDf[col])
        salesDf.addColumn({ column: col, value: enc_val })
     })
     ...
```

1.  接下来，我们将从训练数据集中分离出目标。目标，正如我们从问题陈述中注意到的那样，是销售价格。这对应于最后一列`Item_Outlet_Sales`。在下面的代码片段中，我们将使用`iloc`函数拆分数据集：

```js
...
      let Xtrain, ytrain;
      Xtrain = salesDf.iloc({ columns:         [`1:${salesDf.columns.length - 1}`] })
      ytrain = salesDf['Item_Outlet_Sales']
      console.log(`Training Dataset Shape: ${Xtrain.shape}`)
...
```

1.  接下来，我们将标准化我们的数据集。标准化数据集会强制使每一列都在同一比例上，从而提高模型训练。在下面的代码片段中，我们使用 Danfo.js 的`StandardScaler`来标准化数据集：

```js
      ... 
 let scaler = new dfd.MinMaxScaler()
      scaler.fit(Xtrain)
      Xtrain = scaler.transform(Xtrain)
...
```

1.  最后，为了完成`processData`函数，我们将返回原始张量，如下面的代码片段所示：

```js
...
       return [Xtrain.tensor, ytrain.tensor]
...
```

注意

您可以在此处的代码存储库中查看完整的代码：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/blob/main/Chapter10/sales_predictor/src/data-proc.js`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/blob/main/Chapter10/sales_predictor/src/data-proc.js)。

执行并打印最终的`data_proc.js`文件中的张量应该会给您类似于以下截图中显示的张量：

![图 10.10 - 处理后的 Final BigMart 数据张量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_10.jpg)

图 10.10 - 处理后的 Final BigMart 数据张量

现在您有一个可以处理原始数据集并返回张量的函数，让我们继续使用`tfjs`创建模型。

## 使用 TensorFlow.js 创建模型

正如我们之前提到的，`tfjs`提供了一个 Layers API，可用于定义和创建 ML 模型。Layers API 类似于流行的 Keras API，因此已经熟悉 Keras 的 Python 开发人员可以轻松地将其代码移植到`tfjs`。

Layers API 提供了创建模型的两种方式 - 顺序和模型格式。我们将在以下子部分中简要解释并举例说明这两种方式。

### 创建模型的顺序方式

这是创建模型的最简单和最常见的方式。它只是一个多个模型层的堆叠，其中堆栈中的第一层定义了输入，最后一层定义了输出，而中间层可以有很多。

以下代码片段显示了一个两层顺序模型的示例：

```js
const model = tf.sequential();
// First layer must have an input shape defined.
model.add(tf.layers.dense({units: 32, inputShape: [50]}));
model.add(tf.layers.dense({units: 24})); 
model.add(tf.layers.dense({units: 1}));
```

您会注意到前面的代码片段中，序列中的第一层提供了`inputShape`参数。这意味着模型期望输入有`50`列。

您还可以通过传递层列表来创建顺序层，如下面的代码片段所示：

```js
const model = tf.sequential({
   layers: [tf.layers.dense({units: 32, inputShape: [50]}),
           tf.layers.dense({units: 24}),
           tf.layers.dense({units: 1})]
});
```

接下来，让我们看看模型格式。

### 创建模型的模型方式

使用模型格式创建模型在创建模型时提供了更大的灵活性。与仅接受线性层堆叠的模型不同，使用模型层定义的模型可以是非线性的、循环的，可以像您想要的那样高级或连接。

例如，在以下代码片段中，我们使用模型格式创建了一个两层网络：

```js
const input = tf.input({ shape: [5] });
const denseLayer1 = tf.layers.dense({ units: 16, activation: 'relu' });
const denseLayer2 = tf.layers.dense({ units: 8, activation: 'relu' });
const denseLayer3 = tf.layers.dense({ units: 1 })
const output = denseLayer3.apply(denseLayer2.apply(denseLayer1.apply(input)))
const model = tf.model({ inputs: input, outputs: output });
```

从前面的示例代码中，您可以看到我们明确调用了`apply`函数，并将要连接的层作为参数传递。这样，我们可以构建具有类似图形连接的混合和高度复杂的模型。

您可以在官方`tfjs`文档中了解有关 Layers API 的更多信息：[`js.tensorflow.org/api/latest/#Models`](https://js.tensorflow.org/api/latest/#Models)。

现在您知道如何使用 Layer API 创建模型，我们将在下一节中创建一个简单的三层回归模型。

## 创建一个简单的三层回归模型

回归模型，正如我们在上一章*第九章*，*机器学习基础*中所解释的，是具有连续输出的模型。要使用`tfjs`创建回归模型，我们定义层的堆栈，并在最后一层将`units`的数量设置为`1`。例如，打开代码存储库中的`model.js`文件。在*第 7-11 行*，您应该看到以下顺序模型定义：

```js
...
const model = tf.sequential();
model.add(tf.layers.dense({ inputShape: [11], units: 128, kernelInitializer: 'leCunNormal' }));
model.add(tf.layers.dense({units: 64, activation: 'relu' }));
model.add(tf.layers.dense({units: 32, activation: 'relu' }));
model.add(tf.layers.dense({units: 1}))
...
```

请注意，在第一层中，我们将`inputShape`参数设置为`11`。这是因为我们的 BigMart 数据集中有`11`个训练列。您可以通过打印处理后的张量的形状来确认这一点。在最后一层，我们将`units`属性设置为`1`，因为我们想要预测一个单一的连续值。

中间的层可以有很多，单位可以取任意数量。因此，在本质上，增加中间层会给我们一个更深的模型，增加单位会给我们一个更宽的模型。选择要使用的层不仅取决于问题，还取决于执行多次实验和训练。

有了这几行代码，您已经成功地在`tfjs`中创建了一个三层回归模型。

创建模型后，您通常要做的下一件事是编译模型。那么，编译是什么？编译是为训练和评估准备模型的过程。这意味着在编译阶段，我们必须设置模型的优化器、损失和/或训练指标。

在开始训练之前，`tfjs`模型必须先进行编译。那么，在`tfjs`中如何编译模型呢？这可以通过在已定义的模型上调用`compile`函数，并设置您想要计算的优化器和指标来完成。

在`model.js`文件的*13-17 行*中，我们通过将优化器设置为`Adam`，将`loss`和`metrics`属性设置为`meanSquaredError`来编译了我们的回归模型。请查看以下代码片段：

```js
...
    model.compile({
        optimizer: tf.train.adam(LEARNING_RATE),
        loss: tf.losses.meanSquaredError,
        metrics: ['mse']
    });
...
```

值得一提的是，有不同类型的优化器可供选择；请在[`js.tensorflow.org/api/latest/#Training-Optimizers`](https://js.tensorflow.org/api/latest/#Training-Optimizers)上查看完整列表。选择使用哪种优化器将取决于您的经验，以及多次实验。

在损失方面，问题将告诉您使用哪种损失函数。在我们的情况下，由于这是一个回归问题，我们可以使用**均方误差**（**MSE**）函数。要查看可用损失函数的完整列表，请访问[`js.tensorflow.org/api/latest/#Training-Losses`](https://js.tensorflow.org/api/latest/#Training-Losses)。

最后，在模型训练期间计算和显示的指标方面，我们可以指定多个选项，就像损失一样，指定的指标将取决于您要解决的问题。在我们的情况下，我们也可以计算 MSE。要查看支持的指标的完整列表，请访问[`js.tensorflow.org/api/latest/#Metrics`](https://js.tensorflow.org/api/latest/#Metrics)。

现在您已经定义并编译了模型，我们将继续进行本章的下一个也是最后一个部分，即模型训练。

## 使用处理过的数据集训练模型

`train.js`文件包含了对处理过的数据集进行三层回归模型训练的代码。在接下来的步骤中，我们将带您完成整个模型训练的过程：

1.  首先，让我们使用`processData`函数加载和处理数据集，如下所示：

```js
…
const data = await processData("./dataset/train.csv")
const Xtrain = data[0]
const ytrain = data[1]
…
```

1.  接下来，我们使用`getModel`函数加载模型，如下所示：

```js
…
const model = getModel()
…
```

1.  接下来，非常重要的是，我们在模型上调用`fit`函数，传递训练数据、目标和一些参数，如`epoch`、`batchSize`和`validationSplits`参数，以及一个名为`onEpochEnd`的回调函数，如下所示：

```js
…
    await model.fit(Xtrain, ytrain, {
        batchSize: 24,
        epochs: 20,
        validationSplit: 0.2,
        callbacks: {
            onEpochEnd: async (epoch, logs) => {
                const progressUpdate = `EPOCH (${epoch + 1}): Train MSE: ${Math.sqrt(logs.mse)}, Val MSE:  ${Math.sqrt(logs.val_mse)}\n`
                console.log(progressUpdate);
            }
        }
    });
...
```

让我们了解一下我们传递给`fit`函数的参数的作用，如下所示：

+   `Xtrain`：训练数据。

+   `ytrain`：目标数据。

+   `epoch`：epoch 大小是迭代训练数据的次数。

+   `batchSize`：批量大小是用于计算一个梯度更新的数据点或样本的数量。

+   `validationSplit`：验证分割是一个方便的参数，告诉`tfjs`保留指定百分比的数据用于验证。当我们不想手动将数据集分割成训练集和测试集时，可以使用这个参数。

+   `callbacks`：回调函数，顾名思义，接受在模型训练的不同生命周期中调用的函数列表。回调函数在监控模型训练中非常重要。在这里可以看到完整的回调函数列表：[`js.tensorflow.org/api/latest/#tf.Sequential.fitDataset`](https://js.tensorflow.org/api/latest/#tf.Sequential.fitDataset)。

1.  最后，我们保存模型，以便在进行新预测时使用：

```js
      ...
      await model.save("file://./sales_pred_model")
 ...
```

运行`train.js`文件将加载和处理数据集，加载模型，并对指定数量的 epochs 运行模型训练。我们指定的回调函数(`onEpochEnd`)将在每个 epoch 结束后打印出损失和均方根误差，如下面的截图所示：

![图 10.11 – 显示损失和均方根误差的模型训练日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_11.jpg)

图 10.11 – 显示损失和均方根误差的模型训练日志

就是这样！您已经成功地创建、训练和保存了一个可以使用 TensorFlow.js 预测销售价格的回归模型。在本章的下一个和最后一节中，我们将向您展示如何加载您保存的模型并用它进行预测。

## 使用训练好的模型进行预测

为了进行预测，我们必须加载保存的模型，并在其上调用`predict`函数。TensorFlow.js 提供了一个`loadLayersModel`函数，用于从文件系统加载保存的模型。在以下步骤中，我们将向您展示如何实现这一点：

1.  创建一个名为`predict.js`的新文件。

1.  在`predict.js`文件中，添加以下代码：

```js
const dfd = require("danfojs-node")
const tf = dfd.tf
async function loadModel() {
    const model = await tf.loadLayersModel('file://./sales_pred_model/model.json');
    model.summary()
    return model
}
loadModel()
```

前面的代码从文件路径加载了保存的模型并打印了摘要。摘要的输出应该与下面的截图类似：

![图 10.12 – 保存模型的模型摘要](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_10_12.jpg)

图 10.12 – 保存模型的模型摘要

1.  现在，创建一个名为`predict`的新函数，该函数使用保存的模型进行预测，如下面的代码片段所示：

```js
...
async function predict() {
    //You'll probably have to do some data pre-processing as we did before training
    const data = [0.1, 0.21, 0.25, 0.058, 0.0, 0.0720, 0.111, 1, 0, 0.5, 0.33] //sample processed test data
    const model = await loadModel()
    const value = model.predict(tf.tensor(data, [1, 11])) //cast data to required shape
    console.log(value.arraySync());

}
predict()
```

输出如下：

```js
[ [ 738.65380859375 ] ]
...
```

在前面的函数中，我们在模型上调用`predict`函数，并传递一个具有正确形状（批次，11）的张量，这是我们的模型所期望的。这将返回一个预测的张量，从这个张量中，我们可以得到基础值。从这个值，我们可以得知具有这些特定值的产品大约会售价**美元**（**USD**）$739。

注意

在实际应用中，您通常会从另一个**逗号分隔值**（**CSV**）文件中加载测试数据集，并应用与训练过程中相同的数据处理步骤。本示例使用内联数据点，只是为了演示如何使用保存的模型进行预测。

这就是本章的结束了！恭喜您走到了这一步。我相信您已经学到了很多。在下一章中，我们将通过构建一个更实用的应用程序——一个推荐系统来深入探讨！

# 总结

在这一章中，我们向您介绍了 TensorFlow.js 的基础知识。具体来说，您学习了如何在浏览器和 Node.js 环境中安装 TensorFlow.js，学习了张量和`tfjs`的核心数据结构，学习了核心和层 API，最后，您学会了如何构建、训练和保存回归模型。

在下一章中，我们将深入探讨一个更实用和动手的项目，这里所学到的知识将帮助您使用 TensorFlow.js 和 Danfo.js 构建出色的产品。


# 第十二章：使用 Danfo.js 和 TensorFlow.js 构建推荐系统

在前一章中，我们向您介绍了 TensorFlow.js，并向您展示了如何创建一个简单的回归模型来预测销售价格。在本章中，我们将进一步创建一个推荐系统，可以根据用户的偏好向不同用户推荐电影。通过本章的学习，您将了解推荐系统的工作原理，以及如何使用 JavaScript 构建一个推荐系统。

具体来说，我们将涵盖以下主题：

+   推荐系统是什么？

+   创建推荐系统的神经网络方法

+   构建电影推荐系统

# 技术要求

要在本章中跟进，您将需要以下内容：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox

+   **Node.js**、**Danfo.js**、TensorFlow.js 和（可选）**Dnotebook**已安装在您的系统上

+   稳定的互联网连接用于下载数据集

+   本章的代码可在 GitHub 上找到并克隆：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11)

Danfo.js、TensorFlow.js 和 Dnotebook 的安装说明可以在*第三章**，使用 Danfo.js 入门*，*第十章**，TensorFlow.js 简介*和*第二章**，Dnotebook - JavaScript 交互计算环境*中找到。

# 什么是推荐系统？

**推荐系统**是任何可以预测用户对物品的偏好或有用性评分的系统。利用这个偏好评分，它可以向用户推荐物品。

这里的物品可以是数字产品，如电影、音乐、书籍，甚至衣服。每个推荐系统的目标是能够推荐用户会喜欢的物品。

推荐系统非常受欢迎，几乎无处不在；例如：

+   诸如*Netflix*、*Amazon Prime*、*Hulu*和*Disney+*等电影流媒体平台使用推荐系统向您推荐电影。

+   诸如*Facebook*、*Twitter*和*Instagram*等社交媒体网站使用推荐系统向用户推荐朋友。

+   诸如*Amazon*和*AliExpress*等电子商务网站使用推荐系统向用户推荐衣服、书籍和电子产品等产品。

推荐系统主要是使用用户-物品互动的数据构建的。因此，在构建推荐系统时，通常遵循三种主要方法。这些方法是**协同过滤**、**基于内容的过滤**和**混合方法**。我们将在以下子章节中简要解释这些方法。

## 协同过滤方法

在协同过滤方法中，推荐系统是基于用户的过去行为或历史建模的。也就是说，这种方法利用现有的用户互动，如对物品的评分、喜欢或评论，来建模用户的偏好，从而了解用户喜欢什么。下图显示了协同过滤方法如何帮助构建推荐系统：

![图 11.1 - 基于协同过滤的推荐系统构建方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_01.jpg)

图 11.1 - 基于协同过滤的推荐系统构建方法

在上图中，您可以看到两个观看了相同电影，可能评分相同的用户被分为相似用户，因为左边的人看过的电影被推荐给了右边的人。在基于内容的过滤方法中，推荐系统是基于**物品特征**建模的。也就是说，物品可能预先标记有某些特征，比如类别、价格、流派、大小和收到的评分，利用这些特征，推荐系统可以推荐相似的物品。

下图显示了基于内容的过滤方法构建推荐系统的工作原理：

![图 11.2 - 基于内容的过滤方法构建推荐系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_02.jpg)

图 11.2 - 基于内容的过滤方法构建推荐系统

在上图中，您可以观察到相互相似的电影会被推荐给用户。

## 混合过滤方法

混合方法，顾名思义，是协同和基于内容的过滤方法的结合。也就是说，它结合了两种方法的优点，创建了一个更好的推荐系统。大多数现实世界的推荐系统今天都使用这种方法来减轻各种方法的缺点。

下图显示了将基于内容的过滤方法与协同过滤方法相结合，创建混合推荐系统的一种方式：

![图 11.3 - 构建推荐系统的混合方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_03.jpg)

图 11.3 - 构建推荐系统的混合方法

在上图中，您可以看到我们有两个输入输入混合系统。这些输入进入协同(**CF**)和基于内容的系统，然后这些系统的输出被结合起来。这种组合可以定制，甚至可以作为其他高级系统的输入，比如神经网络。总体目标是通过结合多个推荐系统来创建一个强大的混合系统。

值得一提的是，任何用于创建推荐系统的方法都需要某种形式的数据。例如，在协同过滤方法中，您将需要*用户-物品交互*历史记录，而在基于内容的方法中，您将需要*物品元数据*。

如果您有足够的数据来训练一个推荐系统，您可以利用众多的机器学习和非机器学习技术来对数据进行建模，然后再进行推荐。您可以使用一些流行的算法，比如**K 最近邻**([`en.wikipedia.org/wiki/K-nearest_neighbors_algorithm`](https://en.wikipedia.org/wiki/K-nearest_neighbors_algorithm))、**聚类算法**([`en.wikipedia.org/wiki/Cluster_analysis`](https://en.wikipedia.org/wiki/Cluster_analysis))、**决策树**([`en.wikipedia.org/wiki/Decision_trees`](https://en.wikipedia.org/wiki/Decision_trees))、**贝叶斯分类器**([`en.wikipedia.org/wiki/Naive_Bayes_classifier`](https://en.wikipedia.org/wiki/Naive_Bayes_classifier))，甚至**人工神经网络**([`en.wikipedia.org/wiki/Artificial_neural_networks`](https://en.wikipedia.org/wiki/Artificial_neural_networks))。

在本章中，我们将使用**神经网络**方法来构建推荐系统。我们将在下一节中详细解释这一点。

# 创建推荐系统的神经网络方法

近年来，神经网络在解决机器学习（ML）领域的许多问题时已成为瑞士军刀。这在 ML 突破领域明显，如图像分类/分割和自然语言处理。随着数据的可用性，神经网络已成功用于构建大规模推荐系统，如 Netflix（https://research.netflix.com/research-area/machine-learning）和 YouTube（https://research.google/pubs/pub45530/）使用的系统。

尽管有不同的方法来使用神经网络构建推荐系统，但它们都依赖于一个主要事实：它们需要一种有效的方法来学习项目或用户之间的相似性。在本章中，我们将利用一种称为嵌入的概念来有效地学习这些相似性，以便轻松地为我们的推荐系统提供动力。

但首先，嵌入是什么，为什么我们在使用它们？在下一小节中，我们将简要回答这些问题。

### 什么是嵌入？

嵌入是将离散变量映射到连续或实值变量的映射。也就是说，给定一组变量，例如[好，坏]，嵌入可以将每个离散项映射到*n*维的连续向量 - 例如，好可以表示为[0.1, 0.6, 0.1, 0.8]，坏可以表示为[0.8, 0.2, 0.6, 0.1]，如下图所示：

![图 11.4 - 用实值变量表示离散类别](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_04.jpg)

图 11.4 - 用实值变量表示离散类别

如果您熟悉诸如独热编码（https://en.wikipedia.org/wiki/One-hot）或标签编码（https://machinelearningmastery.com/one-hot-encoding-for-categorical-data/）等编码方案，那么您可能想知道嵌入与它们有何不同。

嗯，嵌入有两个主要的区别，技术上来说，是优势： 

+   嵌入表示可以是小的或大的，具体取决于指定的维度。这与独热编码等编码方案不同，其中表示的维度随着离散类的数量增加而增加。

例如，下图显示了一个独热编码表示中使用的维度随着唯一国家数量的增加而增加：

![图 11.5 - 嵌入和独热编码之间的大小比较](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_05.jpg)

图 11.5 - 嵌入和独热编码之间的大小比较

+   嵌入可以与神经网络中的权重一起学习。这是与其他编码方案相比的主要优势，因为具有此属性，学习的嵌入成为离散类的相似性集群，这意味着您可以轻松找到相似的项目或用户。例如，查看以下证明，您可以看到我们有两组学习的单词嵌入：

![图 11.6 - 嵌入单词并在嵌入空间中显示相似性（重新绘制自：https://medium.com/@hari4om/word-embedding-d816f643140）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_06.jpg)

图 11.6 - 嵌入单词并在嵌入空间中显示相似性（重新绘制自：https://medium.com/@hari4om/word-embedding-d816f643140）

在前面的图中，您可以看到代表男人，女人，国王和皇后的组被传递到嵌入中，结果输出是一个嵌入空间，其中意义相近的单词被分组。这是通过学习的单词嵌入实现的。

那么，我们如何利用嵌入来创建推荐系统呢？嗯，正如我们之前提到的，嵌入可以有效地表示数据，这意味着我们可以使用它们来学习或表示用户-项目的交互。因此，我们可以轻松地使用学习到的嵌入来找到相似的项目进行推荐。我们甚至可以进一步将嵌入与监督机器学习任务相结合。

将学习到的嵌入表示与监督机器学习任务相结合的这种方法，将是我们在下一节中创建电影推荐系统的做法。

# 构建电影推荐系统

要构建一个电影推荐系统，我们需要某种用户-电影交互数据集。幸运的是，我们可以使用由**Grouplens**提供的`MovieLens 100k`数据集（[`grouplens.org/datasets/movielens/100k/`](https://grouplens.org/datasets/movielens/100k/)）。这个数据包含了 1,000 个用户对 1,700 部电影的 100,000 个电影评分。

以下截图显示了数据集的前几行：

![图 11.7 - MovieLens 数据集的前几行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_07.jpg)

图 11.7 - MovieLens 数据集的前几行

从前面的截图中，您可以看到我们有`user_id`，`item_id`（电影）以及用户给予项目（电影）的评分。仅凭这种交互和使用嵌入，我们就可以有效地建模用户的行为，并因此了解他们喜欢什么类型的电影。

要了解我们将如何构建和学习嵌入与神经网络的交互，请参考以下架构图：

![图 11.8 - 我们推荐系统的高层架构](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_08.jpg)

图 11.8 - 我们推荐系统的高层架构

从前面的图表中，您可以看到我们有两个嵌入层，一个用于用户，另一个用于项目（电影）。这两个嵌入层然后在传递到一个密集层之前被合并。

因此，实质上，我们将嵌入与监督学习任务相结合，其中来自嵌入的输出被传递到一个密集层，以预测用户将给出的项目（电影）的评分。

您可能会想，如果我们正在学习预测用户将给出的产品的评分，那么这如何帮助我们进行推荐呢？嗯，诀窍在于，如果我们能有效地预测用户将给一部电影的评分，那么，使用学习到的相似性嵌入，我们就可以预测用户将给所有电影的评分。然后，有了这个信息，我们就可以向用户推荐预测评分最高的电影。

那么，我们如何在 JavaScript 中构建这个看似复杂的推荐系统呢？嗯，在下一个小节中，我们将向您展示如何轻松地使用 TensorFlow.js，结合 Danfo.js，来实现这一点。

## 设置项目目录

您需要成功跟进本章的代码和数据集，这些都可以在本章的代码存储库中找到（[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11)）。

您可以下载整个项目到您的计算机上以便轻松跟进。如果您已经下载了项目代码，那么请导航到您的根目录，其中`src`文件夹可见。

在`src`文件夹中，您有以下文件夹/脚本：

+   `book_recommendation_model`：这是保存训练模型的文件夹。

+   `data`：这个文件夹包含我们的训练数据。

+   `data_proc.js`：这个脚本包含了我们所有的数据处理代码。

+   `model.js`：这个脚本定义并编译了推荐模型。

+   `recommend.js`：这个脚本包含制作推荐的代码。

+   `train.js`：这个脚本包含训练推荐模型的代码。

要快速测试预训练的推荐模型，首先使用`yarn`（推荐）或`NPM`安装所有必要的包，然后运行以下命令：

```js
 yarn recommend
```

这将为用户 ID 为`196`、`880`和`13`的用户推荐`10`、`5`和`20`部电影。如果成功，你应该看到类似以下的输出：

![图 11.9 - 训练推荐系统提供的推荐电影](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_09.jpg)

图 11.9 - 训练推荐系统提供的推荐电影

你也可以通过运行以下命令重新训练模型：

```js
 yarn retrain
```

默认情况下，上述命令将使用批量大小为`128`、时代大小为`5`来重新训练模型，并在完成时将训练好的模型保存到`book_recommender_model`文件夹中。

现在你已经在本地设置了项目，我们将逐步解释每个部分，并解释如何从头开始构建推荐系统。

## 检索和处理训练数据集

我们使用的数据集是从 Grouplens 网站检索的。默认情况下，电影数据（`https://files.grouplens.org/datasets/movielens/ml-100k.zip`）是一个包含制表符分隔文件的 ZIP 文件。为了简单起见，我已经下载并将你在这个项目中需要的两个文件转换成了`CSV`格式。你可以从这个项目的代码库的`data`文件夹中获取这些文件（[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11/src/data`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter11/src/data)）。

主要有两个文件：

+   `movieinfo.csv`：这个文件包含了关于每部电影的元数据，比如标题、描述和链接。

+   `movielens.csv`：这是用户评分数据集。

要使用`movielens`数据集，我们必须用 Danfo.js 读取数据集，处理数据，然后将其转换为我们可以传递给神经网络的张量。

在项目的代码中，打开`data_proc.js`脚本。这个脚本导出了一个名为`processData`的主要函数，代码如下：

```js
...
    const nItem = (moviesDF["item_id"]).max()
    const nUser = (moviesDF["user_id"]).max()
    const moviesIdTrainTensor = (moviesDF["item_id"]).tensor
    const userIdTrainTensor = (moviesDF["user_id"]).tensor
    const targetData = (moviesDF["rating"]).tensor
    return {
        trainingData: [moviesIdTrainTensor, userIdTrainTensor],
        targetData,
        nItem,
        nUser
    }
...
```

那么，在上述代码中我们在做什么呢？幸运的是，我们不需要进行太多的数据预处理，因为`user_id`、`item_id`和`ratings`列已经是数字形式。所以，我们只是做了两件事：

+   检索物品和用户列的最大 ID。这个数字，称为**词汇量大小**，将在创建我们的模型时传递给嵌入层。

+   检索和返回用户、物品和评分列的基础张量。用户和物品张量将作为我们的训练输入，而评分张量将成为我们的监督学习目标。

现在你知道如何处理数据了，让我们开始使用 TensorFlow.js 构建神经网络。

## 构建推荐模型

我们的推荐模型的完整代码可以在`model.js`文件中找到。这个模型使用了混合方法，就像我们在高级架构图中看到的那样（见*图 11.8*）。

注意

我们正在使用我们在*第十章**TensorFlow.js 简介*中介绍的 Model API 来创建网络。这是因为我们正在创建一个复杂的架构，我们需要更多的控制输入和输出。

在接下来的步骤中，我们将解释模型并展示创建它的相应代码：

1.  `user`和另一个来自物品：

```js
...
const itemInput = tf.layers.input({ name: "itemInput", shape: [1] })
const userInput = tf.layers.input({ name: "userInput", shape: [1] })
...
```

注意，输入的形状参数设置为`1`。这是因为我们的输入张量是具有`1`维的向量。

1.  `InputDim`：这是嵌入向量的词汇量大小。最大整数索引为`+ 1`。

b) `OutputDim`：这是用户指定的输出维度。也就是说，它用于配置嵌入向量的大小。

接下来，我们将合并这些嵌入层。

1.  `dot`乘积，将输出扁平化，并将输出传递给一个密集层：

```js
...
const mergedOutput = tf.layers.dot({ axes: 0}).apply([itemEmbedding, userEmbedding])
const flatten = tf.layers.flatten().apply(mergedOutput)
const denseOut = tf.layers.dense({ units: 1, activation: "sigmoid", kernelInitializer: "leCunUniform" }).apply(flatten)
...
```

通过上述输出，我们现在可以使用 Models API 定义我们的模型。

1.  最后，我们将定义并编译模型，如下面的代码片段所示：

```js
...
const model = tf.model({ inputs: [itemInput, userInput],  outputs: denseOut })
      model.compile({
        optimizer: tf.train.adam(LEARNING_RATE),
        loss: tf.losses.meanSquaredError
      });
...
```

上述代码使用 Models API 来定义输入和输出，然后调用 compile 方法，该方法接受训练优化器（Adam 优化器）和损失函数（均方误差）。您可以在`model.js`文件中查看完整的模型代码。

有了模型架构定义，我们就可以开始训练模型。

## 训练和保存推荐模型

模型的训练代码可以在`train.js`文件中找到。此代码有两个主要部分。我们将在这里看到两者。

第一部分，如下面的代码块所示，使用批量大小为`128`，时代大小为`5`，并且将`10`%的数据用于模型验证的验证分割来训练模型，这部分数据是为了模型验证而保留的：

```js
...
await model.fit(trainingData, targetData, {
        batchSize: 128,
        epochs: 5,
        validationSplit: 0.1,
        callbacks: {
            onEpochEnd: async (epoch, logs) => {
                const progressUpdate = `EPOCH (${epoch + 1}): Train MSE: ${Math.sqrt(logs.loss)}, Val MSE:  ${Math.sqrt(logs.val_loss)}\n`
                console.log(progressUpdate);
            }
        }
    });
...
```

在上述训练代码中，我们在每个训练时代之后打印了损失。这有助于我们跟踪训练进度。

下面的代码块将训练好的模型保存到提供的文件路径。在我们的情况下，我们将其保存到`movie_recommendation_model`文件夹中：

```js
...
await model.save(`file://${path.join(__dirname, "movie_recommendation_model")}`)
...
```

请注意此文件夹的名称，因为我们将在下一小节中使用它进行推荐。

要训练模型，您可以在`src`文件夹中运行以下命令：

```js
yarn train 
```

或者，您也可以直接使用`node`运行`train.js`：

```js
node train.js
```

这将开始指定数量的时代模型训练，并且一旦完成，将模型保存到指定的文件夹。训练完成后，您应该有类似以下的输出：

![图 11.10 - 推荐模型的训练日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_11_10.jpg)

图 11.10 - 推荐模型的训练日志

一旦您有了训练好并保存的模型，您就可以开始进行电影推荐。

## 使用保存的模型进行电影推荐

`recommend.js`文件包含了进行推荐的代码。我们还包括了一个名为`getMovieDetails`的实用函数。此函数将电影 ID 映射到电影元数据，以便我们可以显示有用的信息，例如电影的名称。

但是我们如何进行推荐呢？由于我们已经训练了模型来预测用户对一组电影的评分，我们可以简单地将用户 ID 和所有电影传递给模型来进行评分预测。

有了所有电影的评分预测，我们可以简单地按降序对它们进行排序，然后返回前几部电影作为推荐。

要做到这一点，请按照以下步骤进行：

1.  首先，我们必须获取所有唯一的电影 ID 进行预测：

```js
...
const moviesDF = await dfd.read_csv(moviesDataPath)
const uniqueMoviesId = moviesDF["item_id"].unique().values
const uniqueMoviesIdTensor = tf.tensor(uniqueMoviesId)
...
```

1.  接下来，我们必须构建一个与电影 ID 张量长度相同的用户张量。该张量将在所有条目中具有相同的用户 ID，因为对于每部电影，我们都在预测同一用户将给出的评分：

```js
...
const userToRecommendForTensor = tf.fill([uniqueMoviesIdTensor.shape[0]], userId)
...
```

1.  接下来，我们必须加载模型并通过传递电影和用户张量作为输入来调用`predict`函数：

```js
...
const model = await loadModel()
      const ratings = model.predict([uniqueMoviesIdTensor,
   userToRecommendForTensor])
...
```

这将返回一个张量，其中包含用户将给每部电影的预测评分。

1.  接下来，我们必须构建一个包含名为`movie_id`（唯一电影 ID）和`ratings`（用户对每部电影的预测评分）的两列的 DataFrame：

```js
...
const recommendationDf = new dfd.DataFrame({
        item_id: uniqueMoviesId,
        ratings: ratings.arraySync()
     })
... 
```

1.  将预测评分和相应的电影 ID 存储在 DataFrame 中有助于我们轻松地对评分进行排序，如下面的代码所示：

```js
...
    const topRecommendationsDF = recommendationDf
        .sort_values({
            by: "ratings",
            ascending: false
        })
        .head(top) //return only the top rows
...
```

1.  最后，我们必须将排序后的电影 ID 数组传递给`getMovieDetails`实用函数。此函数将每个电影 ID 映射到相应的元数据，并返回一个包含两列（电影标题和电影发行日期）的 DataFrame，如下面的代码所示：

```js
...
const movieDetailsDF = await getMovieDetails(topRecommendationsDF["movie_id"].values)
...
```

`recommend.js`文件在`src`文件夹中包含了完整的推荐代码，包括将电影 ID 映射到其元数据的实用函数。

要测试推荐，您需要调用`recommend`函数并传递电影 ID 和您想要的推荐数量，如下面的示例所示：

```js
recommend(196, 10) // Recommend 10 movies for user with id 196
```

上述代码在控制台中给出了以下输出：

```js
[
  'Remains of the Day, The (1993)',
  'Star Trek: First Contact (1996)',
  'Kolya (1996)',
  'Men in Black (1997)',
  'Hunt for Red October, The (1990)',
  'Sabrina (1995)',
  'L.A. Confidential (1997)',
  'Jackie Brown (1997)',
  'Grease (1978)',
  'Dr. Strangelove or: How I Learned to Stop Worrying and Love the Bomb (1963)'
]
```

就是这样！您已成功使用神经网络嵌入创建了一个推荐系统，可以高效地向不同用户推荐电影。利用本章学到的概念，您可以轻松地创建不同的推荐系统，可以推荐不同的产品，如音乐、书籍和视频。

# 总结

在本章中，我们成功地构建了一个推荐系统，可以根据用户的偏好向他们推荐电影。首先，我们定义了推荐模型是什么，然后简要讨论了设计推荐系统的三种方法。接着，我们谈到了神经网络嵌入以及为什么决定使用它们来创建我们的推荐模型。最后，我们通过构建一个电影推荐模型，将学到的所有概念整合起来，可以向用户推荐指定数量的电影。

通过本章学到的知识，您可以轻松地创建一个可以嵌入到 JavaScript 应用程序中的推荐系统。

在下一章，您将使用 Danfo.js 和 Twitter API 构建另一个实际应用程序。


# 第十三章：构建 Twitter 分析仪表板

本章的主要目标是展示如何使用 Danfo.js 在后端和前端构建全栈 Web 分析平台。

为了演示这一点，我们将构建一个小型的单页面 Web 应用程序，在这个应用程序中，您可以搜索 Twitter 用户，获取他们在特定日期被提及的所有推文，并进行一些简单的分析，比如情感分析，从数据中得出一些见解。

在本章中，我们将研究构建 Web 应用程序的以下主题：

+   设置项目环境

+   构建后端

+   构建前端

# 技术要求

本章需要以下内容：

+   React.js 的知识

+   本章的代码在这里可用：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter12`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter12)

# 设置项目环境

对于这个项目，我们将构建一个既有后端又有前端的单个网页。我们将使用 Next.js 框架来构建应用程序。Next.js 使您能够快速轻松地构建后端和前端。我们还将使用`tailwindcss`，就像我们之前为一些项目所做的那样，比如无代码环境项目。

设置我们的项目环境与 Next.js 包含默认的`tailwindcss`配置，我们只需要运行以下命令：

```js
$ npx create-next-app -e with-tailwindcss twitterdashboard
```

`npx`命令运行`create-next-app`，它在`twitterdashboard`目录中创建了 Next.js 样板代码，包括`tailwindcss`配置。请注意，`twitterdashboard`目录（也称为*项目名称*）可以根据您的选择命名。如果一切安装成功，您应该会得到以下截图中显示的输出：

![图 12.1 – 代码环境设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_01.jpg)

图 12.1 – 代码环境设置

现在我们已经完成了安装，如果一切正常工作，您应该在项目中有以下文件：

![图 12.2 – 目录结构](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_02.jpg)

图 12.2 – 目录结构

最后，为了测试项目是否安装成功并准备就绪，让我们运行以下命令：

```js
$ npm run dev
```

这个命令应该自动启动应用程序并打开浏览器，显示以下界面：

![图 12.3 – Next.js UI](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_03.jpg)

图 12.3 – Next.js UI

对于这个项目，我们将修改*图 12.3*中显示的界面以适应我们的口味。

现在代码环境已经设置好了，让我们继续创建我们的应用程序。

# 构建后端

在本节中，我们将学习如何为我们的应用程序创建以下 API：

+   `/api/tweet`：这个 API 负责获取 Twitter 用户并获取他们的数据。

+   `/api/nlp`：这个 API 负责对获取的用户数据进行情感分析。

这些 API 将被前端组件所使用，并将用于创建不同的可视化和分析。让我们从创建用于获取 Twitter 用户数据的 API 开始。

## 构建 Twitter API

在本节中，我们将构建一个 API，使得轻松获取 Twitter 用户被提及的推文。从每条推文中，我们将获取它们的元数据，比如文本、发送者的姓名、喜欢和转发的次数、用于发推的设备以及推文创建的时间。

为了构建用于获取 Twitter 用户数据的 Twitter API，并将其结构化为我们喜欢的形式，以便在前端轻松使用，我们需要安装一个工具，使其更容易与主要的 Twitter 开发者 API 进行交互。在以下命令中，我们将安装`twit.js`以便轻松访问和处理 Twitter API：

```js
$ npm i twit
```

一旦安装了`twit`，我们需要对其进行配置。为了使用`twit`，我们需要各种 Twitter 开发者密钥，比如以下内容：

```js
consumer_key='....',
consumer_secret='....',
access_token='.....',
access_token_secret='.....'
```

如果您没有这些密钥，您将需要创建一个 Twitter 开发者账户，然后申请通过[`developer.twitter.com/`](https://developer.twitter.com/)获得 API 访问权限。如果获得使用 Twitter API 的权限，您可以访问[`developer.twitter.com/en/apps`](https://developer.twitter.com/en/apps)创建一个应用程序并设置您的凭证密钥。

注意

获取 Twitter API 可能需要几天的时间，这取决于您描述用例的方式。要获得关于设置 Twitter API 和获取必要密钥的逐步指南以及视觉辅助，请按照这里的步骤：[`realpython.com/twitter-bot-python-tweepy/#creating-twitter-api-authentication-credentials`](https://realpython.com/twitter-bot-python-tweepy/#creating-twitter-api-authentication-credentials)。

在获得项目所需的 Twitter 开发者密钥之后，我们将在我们的代码中使用它们。为了防止将密钥暴露给公众，让我们创建一个名为`.env.local`的文件，并在这个文件中添加我们的 API 密钥，如下面的代码块所示：

```js
CONSUMER_KEY='Put in your CONSUMER_KEY',
CONSUMER_SECRET='Your CONSUMER_SECRET',
ACCESS_TOKEN ='Your ACCESS_TOKEN',
ACCESS_TOKEN_SECRET='Your ACCESS_TOKEN_SECRET'
```

在 Next.js 中，所有 API 都是在`/pages/api`文件夹中创建的。Next.js 使用`pages/`文件夹中的文件结构来创建 URL 路由。例如，如果您在`pages/`文件夹中有一个名为`login.js`的文件，那么`login.js`中的内容将在`http://localhost:3000/login`中呈现。

前面的段落展示了基于文件名和结构在 Next.js 中为网页创建路由的方法。同样的方法也适用于在 Next.js 中创建 API。

假设我们在`pages/api`中创建了一个用于注册的 API，名为`signup.js`。这个 API 将自动在`http://localhost:3000/api/signup`中可用，如果我们要在应用程序内部使用这个 API，我们可以这样调用它：`/api/signup`。

对于我们的`/api/tweet` API，让我们在`pages/api/`中创建一个名为`tweet.js`的文件，并按照以下步骤更新文件：

1.  首先，我们导入`twit.js`，然后创建一个函数来清理每个推文：

```js
const Twit = require('twit')
function clean_tweet(tweet) {
  tweet = tweet.normalize("NFD") //normalize text
  tweet = tweet.replace(/(RT\s(@\w+))/g, '') //remove Rt tag followed by an @ tag
  tweet = tweet.replace(/(@[A-Za-z0-9]+)(\S+)/g, '') // remove user name e.g @name
  tweet = tweet.replace(/((http|https):(\S+))/g, '') //remove url
  tweet = tweet.replace(/[!#?:*%$]/g, '') //remove # tags
  tweet = tweet.replace(/[^\s\w+]/g, '') //remove punctuations
  tweet = tweet.replace(/[\n]/g, '') //remove newline
  tweet = tweet.toLowerCase().trim() //trim text
  return tweet
}
```

`clean_tweet`函数接受推文文本，规范化文本，移除标签字符，用户名称，URL 链接和换行符，然后修剪文本。

1.  然后我们创建一个名为`twitterApi`的函数，用于创建我们的 API：

```js
export default function twitterAPI(req, res) {
  // api code here
}
```

`twitterApi`函数接受两个参数，`req`和`res`，分别是服务器请求和响应的参数。

1.  我们现在将使用必要的代码更新`twitterApi`：

```js
if (req.method === "POST") {
    const { username } = req.body

    const T = new Twit({
      consumer_key: process.env.CONSUMER_KEY,
      consumer_secret: process.env.CONSUMER_SECRET,
      access_token: process.env.ACCESS_TOKEN,
      access_token_secret: process.env.ACCESS_TOKEN_SECRET,
      timeout_ms: 60 * 1000,  // optional HTTP request timeout to apply to all requests.
      strictSSL: true,     // optional - requires SSL certificates to be valid.
    })
}
```

首先，我们检查`req.method`请求方法是否为`POST`方法，然后我们从通过搜索框发送的请求体中获取用户名。

`Twit`类被实例化，并且我们的 Twitter API 密钥被传入。由于我们的 Twitter 开发者 API 密钥存储为`.env.local`中的环境密钥，我们可以使用`process.env`轻松访问每个密钥。

1.  我们已经使用我们的 API 密钥配置了`twit.js`。现在让我们搜索提到用户的所有推文：

```js
T.get('search/tweets', { q: `@${username}`, tweet_mode: 'extended' }, function (err, data, response) {
  let dfData = {
    text: data.statuses.map(tweet => clean_tweet(tweet.full_text)),
    length: data.statuses.map(tweet => clean_tweet(tweet.full_text).split(" ").length),
    date: data.statuses.map(tweet => tweet.created_at),
    source: data.statuses.map(tweet => tweet.source.replace(/<(?:.|\n)*?>/gm, '')),
    likes: data.statuses.map(tweet => tweet.favorite_count),
    retweet: data.statuses.map(tweet => tweet.retweet_count),
    users: data.statuses.map(tweet => tweet.user.screen_name)
  }
  res.status(200).json(dfData)
})
```

我们使用`T.get`方法中的`search/tweets` API 搜索所有推文。然后我们传入包含我们想要搜索的用户的用户名的`param`对象。

创建一个`dfData`对象来根据我们希望的 API 输出响应的方式对数据进行结构化。`dfData`包含以下键，这些键是我们想要从推文中提取的元数据：

+   `text`：推文中的文本

+   `length`：推文的长度

+   `date`：推文发布日期

+   `source`：用于创建推文的设备

+   `likes`：推文的点赞数

+   `retweet`：推文的转发数

+   `users`：创建推文的用户

前面列表中的元数据是从前面代码中的`T.get()`方法返回的`search/tweets`中提取的 JSON 数据中提取的。从这个 JSON 数据中提取的所有元数据都包含在一个名为`statuses`的对象数组中，以下是 JSON 数据的结构：

```js
{
  statuses:[{
    ......
  },
    ......
  ]
}
```

Twitter API 已经创建并准备好使用。让我们继续创建情感分析 API。

## 构建文本情感 API

从`/api/tweet` API 中，我们将获取结构化的 JSON 数据，然后进行情感分析。

数据的情感分析将通过`/api/nlp`路由获取。因此，在本节中，我们将看到如何为我们的 Twitter 数据创建情感分析 API。

让我们在`/pages/api/`文件夹中创建一个名为`nlp.js`的文件，并按以下步骤更新它：

1.  我们将使用`nlp-node.js`包进行情感分析。我们还将使用`danfojs-node`进行数据预处理，因此让我们安装这两个包：

```js
$ npm i node-nlp danfojs-node
```

1.  我们从`nlp-node`和`danfojs-node`中导入`SentimentAnalyzer`和`DataFrame`：

```js
const { SentimentAnalyzer } = require('node-nlp')
const { DataFrame } = require("danfojs-node")
```

1.  接下来，我们将创建一个默认的`SentimentApi`导出函数，其中将包含我们的 API 代码：

```js
export default async function SentimentApi(req, res) {

}
```

1.  然后，我们将检查请求方法是否为`POST`请求，然后对从请求体获取的数据进行一些数据预处理：

```js
if (req.method === "POST") {
    const sentiment = new SentimentAnalyzer({ language: 'en' })
    const { dfData, username } = req.body
  //check if searched user is in the data
    const df = new DataFrame(dfData)
    let removeUserRow = df.query({
      column: "users",
      is: "!=",
      to: username
    })
    //filter rows with tweet length <=1
    let filterByLength = removeUserRow.query({
      column: "length",
      is: ">",
      to: 1
    })
. . . . .
}
```

在上述代码中，我们首先实例化了`SentimentAnalyzer`，然后将其语言配置设置为英语（`en`）。然后我们从请求体中获取了`dfData`和`username`。

为了分析和从数据中创建见解，我们只想考虑用户与他人的互动，而不是他们自己；也就是说，我们不想考虑用户回复自己的推文。因此，我们从从`dfData`生成的 DataFrame 中过滤出用户的回复。

有时，一条推文可能只包含一个标签或使用`@`符号引用用户。但是，在我们之前的清理过程中，我们删除了标签和`@`符号，这将导致一些推文最终不包含任何文本。因此，我们将创建一个新的`filterBylength` DataFrame，其中将包含非空文本：

1.  我们将继续创建一个对象，该对象将包含用户数据的整体情感计数，并在我们调用 API 时发送到前端：

```js
let data = {
  positive: 0,
  negative: 0,
  neutral: 0
}
let sent = filterByLength["text"].values
for (let i in sent) {
  const getSent = await sentiment.getSentiment(sent[i])
  if (getSent.vote === "negative") {
    data.negative += 1
  } else if (getSent.vote === "positive") {
    data.positive += 1
  } else {
    data.neutral += 1
  }
}
res.status(200).json(data)
```

在上述代码中，我们创建数据对象来存储整体情感分析。由于情感分析只会在`filterByLength` DataFrame 中的文本数据上执行，我们提取文本列值。

1.  然后，我们循环遍历提取的文本列值，并将它们传递给`sentiment.getSentiment`。对于传递给`sentiment.getSentiment`的每个文本，将返回以下类型的对象：

```js
{
  score: 2.593,
  numWords: 36,
  numHits: 8,
  average: 0.07202777777777777,
  type: 'senticon',
  locale: 'en',
  vote: 'positive'
}
```

对于我们的用例，我们只需要`vote`的键值。因此，我们检查文本的`vote`值是`negative`、`positive`还是`neutral`，然后递增数据对象中每个键的计数。

因此，每当调用`/api/nlp`时，我们应该收到以下响应，例如：

```js
{
  positive: 20,
  negative: 12,
  neutral: 40
}
```

在本节中，我们看到了如何在 Next.js 中创建 API，更重要的是，我们看到了在后端使用 Danfo.js 是多么方便。在下一节中，我们将实现应用程序的前端部分。

# 构建前端

对于我们的前端设计，我们将使用 Next.js 默认的 UI，如*图 12.3*所示。我们将为我们的前端实现以下一组组件：

+   `Search`组件：创建一个搜索框来搜索 Twitter 用户。

+   `ValueCount`组件：获取唯一值的计数并使用条形图或饼图绘制它。

+   `Plot`组件：此组件用于以条形图的形式绘制我们的情感分析。

+   `Table`组件：用于以表格形式显示获取的用户数据。

在接下来的几节中，我们将实现上述组件列表。让我们开始实现`Search`组件。

## 创建搜索组件

`Search`组件是设置应用程序运行的主要组件。它提供了输入字段，可以在其中输入 Twitter 用户的名称，然后进行搜索。`search`组件使我们能够调用创建的两个 API：`/api/tweet`和`/api/nlp`。

在我们的`twitterdashboard`项目目录中，让我们创建一个名为`Search.js`的目录，并在该目录中创建一个名为`Search.js`的 JavaScript 文件。

在`Search.js`中，让我们输入以下代码：

```js
import React from 'react'
export default function Search({ inputRef, handleKeyEvent, handleSubmit }) {
  return (
    <div className='border-2 flex justify-between p-2 rounded-md  md:p-4'>
      <input id='searchInput' 
        type='text' 
        placeholder='Search twitter user' 
        className='focus:outline-none'
        ref={inputRef} 
        onKeyPress={handleKeyEvent}
      />
      <button className='focus:outline-none' 
            onClick={() => { handleSubmit() }}>
            <img src="img/search.svg" />
     </button>
    </div>
  )
}
```

在上述代码中，我们创建了一个带有以下一组 props 的`Search`函数：

+   `inputRef`：此 prop 是从`useRef` React Hook 获取的。它将用于跟踪搜索输入字段的当前值。

+   `handleKeyEvent`：这是一个事件函数，将被传递给搜索输入字段，以便通过按*Enter*键进行搜索。

+   `handleSubmit`：这是一个函数，每次单击搜索按钮时都会激活。`handleSubmit`函数负责调用我们的 API。

让我们继续前往`/pages/index.js`，通过导入`Search`组件并根据以下步骤创建所需的 props 列表来更新文件：

1.  首先，我们将导入 React、React Hooks 和`Search`组件：

```js
import React, { useRef, useState } from 'react'
import Search from '../components/Search'
```

1.  然后，我们将创建一些状态集：

```js
let [data, setData] = useState() // store tweet data from /api/tweet
let [user, setUser] = useState() // store twitter usersname 
let [dataNlp, setDataNlp] = useState() // store data from /api/nlp
let inputRef = useRef() // monitor the current value of search input field
```

1.  然后，我们将创建`handleSubmit`函数来调用我们的 API 并更新状态数据：

```js
const handleSubmit = async () => {
    const res = await fetch(
      '/api/tweet',
      {
        body: JSON.stringify({
        username: inputRef.current.value
        }),
        headers: {
        'Content-Type': 'application/json'
        },
        method: 'POST'
        }
    )
    const result = await res.json()
. . . . . . .
}
```

首先，在`handleSubmit`中，我们调用`/api/tweet` API 来获取用户的数据。在`fetch`函数中，我们获取`inputRef.current.value`搜索字段的当前值，并将其转换为 JSON 对象，然后传递到请求体中。然后使用变量 result 来从 API 获取 JSON 数据。

1.  我们进一步更新`handleSubmit`函数以从`/api/nlp`获取数据：

```js
const resSentiment = await fetch(
      '/api/nlp',
      {
        body: JSON.stringify({
        username: inputRef.current.value,
        dfData: result
        }),
        headers: {
        'Content-Type': 'application/json'
        },
        method: 'POST'
    },
    )
const sentData = await resSentiment.json()
```

上述代码与*步骤 3*中的代码相同。唯一的区别是我们调用`/api/nlp` API，然后将*步骤 3*中的结果数据和从搜索输入字段获取的用户名传递到请求体中。

1.  然后我们在`handleSubmit`中更新以下状态：

```js
setDataNlp(sentData)
setUser(inputRef.current.value)
setData(result)
```

1.  接下来，我们将创建`handleKeyEvent`函数以通过按*Enter*键进行搜索：

```js
const handleKeyEvent = async (event) => {
    if (event.key === 'Enter') {
      await handleSubmit()
    }
  }
```

在上述代码中，我们检查按键是否为*Enter*键，如果是，则调用`handleSubmit`函数。

1.  最后，我们调用我们的`Search`组件：

```js
<Search inputRef={inputRef} handleKeyEvent={handleKeyEvent} handleSubmit={handleSubmit} />
```

记住，我们说过我们将使用 Next.js 的默认 UI。因此，在`index.js`中，让我们将`Welcome to Next.js`转换为`Welcome to Twitter Dashboard`。

更新`index.js`后，您可以在`http://localhost:3000/`检查浏览器的更新。您将看到以下更改：

![图 12.4 - index.js 更新为搜索组件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_04.jpg)

图 12.4 - index.js 更新为搜索组件

`Search`组件已经实现并融入到主应用程序中，所有必需的状态数据都可以轻松地由`Search`组件更新。让我们继续实现`ValueCounts`组件。

## 创建 ValueCounts 组件

我们将为从`/api/tweet`获取的数据创建一个简单的分析。这个分析涉及检查列中唯一值存在的次数。我们将获得`source`列和`users`列的值计数。

`source`列的值计数告诉我们其他 Twitter 用户用于与我们搜索的用户进行交互的设备。`users`列的值计数告诉我们与我们搜索的用户互动最多的用户。

注意

这里使用的代码是从*第八章*的*实现图表组件*部分中复制的，*创建无代码数据分析/处理系统*。此部分的代码可以在此处获取：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter12/components/ValueCounts.js`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js-/blob/main/Chapter12/components/ValueCounts.js)。这里大部分代码不会在这里详细解释。

让我们转到`components/`目录并创建一个名为`ValueCounts.js`的文件，然后按以下步骤更新它：

1.  首先，我们导入必要的模块：

```js
import React from "react"
import { DataFrame } from 'danfojs/src/core/frame'
import { Pie as PieChart } from "react-chartjs-2";
import { Bar as BarChart } from 'react-chartjs-2';
```

1.  然后，我们创建一个名为`ValueCounts`的函数：

```js
export default function ValueCounts({ data, column, username, type }) {

}
```

该函数接受以下 props：

a) `data`：这是来自`/api/tweet`的数据。

b) `column`：我们要获取值计数的列的名称。

c) `username`：来自搜索字段的输入用户名。

d) `type`：我们要绘制的图表类型。

1.  接下来，我们更新`ValueCounts`函数：

```js
const df = new DataFrame(data)
const removeUserData = df.query({
  column: "users",
  is: "!=",
  to: username
})
const countsSeries = removeUserData[column].value_counts()
const labels = countsSeries.index
const values = countsSeries.values
```

在上述代码中，我们首先从数据创建一个 DataFrame，然后过滤掉包含搜索用户的行，因为我们不希望用户与自己交互的推文。然后，我们从传入的列中提取`value_counts`值。从创建的`countSeries`变量中，我们生成标签和值，这将用于绘制我们的图表。

1.  然后，我们创建一个名为`dataChart`的图表数据变量，它将符合`chart`组件所接受的格式：

```js
const dataChart = {
    labels: labels,
    datasets: [{
      . . . . 
      data: values,
    }]
  };
```

`dataChart`对象包含在*步骤 3*中创建的标签和值。

1.  我们创建一个条件渲染来检查要绘制的图表类型：

```js
if (type === "BarChart") {
   return (
     <div className="max-w-md">
     <BarChart data={dataChart} options={options} width="100" height="100" />
     </div>
)
} else {
  return (<div className="max-w-md">
        <PieChart data={dataChart} options={options} width="100" height="100" />
    </div>)
}
```

`ValueCounts`组件已设置。

现在，我们可以使用以下步骤将`ValueCounts`组件导入`index.js`：

1.  我们导入`ValueCounts`：

```js
import dynamic from 'next/dynamic'
const DynamicValueCounts = dynamic(
  () => import('../components/ValueCounts'),
  { ssr: false }
)
```

我们导入`ValueCounts`的方式与导入`Search`组件的方式不同。这是因为在`ValueCounts`中，我们使用了 TensorFlow.js 中的一些核心浏览器特定工具，这是 Danfo.js 所需的。因此，我们需要防止 Next.js 从服务器渲染组件，以防止出现错误。

为了防止 Next.js 从服务器渲染组件，我们使用`next/dynamic`，然后将要导入的组件包装在`dynamic`函数中，并将`ssr`键设置为`false`。

注意

要了解有关`next/dynamic`的更多信息，请访问[`nextjs.org/docs/advanced-features/dynamic-import`](https://nextjs.org/docs/advanced-features/dynamic-import)。

1.  我们调用`ValueCounts`组件，现在命名为`DynamicValueCounts`：

```js
{typeof data != "undefined" && <DynamicValueCounts data={data} column={"source"} type={"PieChart"} />}
```

我们检查状态数据是否未定义，并且用户数据是否已从`/api/tweet`获取。如果是这样，我们就为`source`列呈现`ValueCounts`组件。

1.  让我们还为`users`列添加`ValueCounts`：

```js
{typeof data != "undefined" && <DynamicValueCounts data={data} column={"users"} username={user} type={"BarChart"} />}
```

我们为用户的`ValueCounts`图表指定`BarChart`，并为`ValueCounts`源指定`PieChart`。

以下显示了每当搜索用户时，`ValueCounts`显示源和用户交互的显示：

![图 12.5 – 源和用户列的 ValueCounts 图表结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_05.jpg)

图 12.5 – 源和用户列的 ValueCounts 图表结果

值计数已完成并且工作正常。让我们继续从`/api/nlp`获取的情感分析数据创建一个图表。

## 创建情感分析的图表组件

当用户使用搜索字段搜索用户时，`sentiData`状态将更新为包含来自`/api/nlp`的情感数据。在本节中，我们将为数据创建一个`Plot`组件。

让我们在`components/`目录中创建一个`Plot.js`文件，并按照以下步骤进行更新：

1.  首先，我们导入所需的模块：

```js
import React from "react"
import { Bar as BarChart } from 'react-chartjs-2';
```

1.  然后，我们创建一个名为`Plot`的函数来绘制情感数据的图表：

```js
export default function Plot({ data }) {
  const dataChart = {
    labels: Object.keys(data),
    datasets: [{
    . . . . . . . .
    data: Object.values(data),
    }]
  };
  return (
    <div className="max-w-md">
      <BarChart data={dataChart} options={options} width="100" height="100" />
    </div>
  )
}
```

该函数接受一个`data`属性。然后我们创建一个包含`chart`组件格式的`dataChart`对象。我们通过获取`data`属性中的键来指定图表标签，并通过获取`data`属性的值来指定`dataChart`中键数据的值。`dataChart`对象传递到`BarChart`组件中。`Plot`组件现在用于情感分析图表。

1.  下一步是在`index.js`中导入`Plot`组件并调用它：

```js
import Plot from '../components/Plot'
. . . . . . 

{typeof dataNlp != "undefined" && <Plot data={dataNlp} />}
```

通过在`index.js`中进行上述更新，每当搜索用户时，我们应该看到情感分析的以下图表：

![图 12.6 – 情感分析图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_06.jpg)

图 12.6 – 情感分析图表

情感分析已经完成并完全集成到`index.js`中。让我们继续创建`Table`组件来显示我们的用户数据。

## 创建 Table 组件

我们将实现一个`Table`组件来显示获取的数据。

注意

表格实现与*第八章*中创建的 DataTable 实现相同，*创建无代码数据分析/处理系统*。有关代码的更好解释，请查看*第八章*，*创建无代码数据分析/处理系统*。

让我们在`components/`目录中创建一个`Table.js`文件，并按以下步骤更新文件：

1.  我们导入了必要的模块：

```js
import React from "react";
import ReactTable from 'react-table-v6'
import { DataFrame } from 'danfojs/src/core/frame'
import 'react-table-v6/react-table.css'
```

1.  我们创建了一个名为`Table`的函数：

```js
export default function DataTable({ dfData, username }) {

}
```

该函数接受`dfData`（来自`/api/nlp`的情感数据）和`username`（来自搜索字段）作为 props。

1.  我们使用以下代码更新函数：

```js
const df = new DataFrame(dfData)
const removeUserData = df.query({
  column: "users",
  is: "!=",
  to: username
})
const columns = removeUserData.columns
const values = removeUserData.values
```

我们从`dfData`创建一个 DataFrame，过滤掉包含用户推文的行，然后提取 DataFrame 的列名和值。

1.  然后我们将此列格式化为`ReactTable`接受的格式：

```js
const dataColumns = columns.map((val, index) => {
    return {
      Header: val,
      accessor: val,
      Cell: (props) => (
        <div className={val || ''}>
        <span>{props.value}</span>
        </div>
      ),
      . . . . . .
    }
  });
```

1.  我们还将值格式化为`ReactTable`接受的格式：

```js
const data = values.map(val => {
    let rows_data = {}
    val.forEach((val2, index) => {
      let col = columns[index];
      rows_data[col] = val2;
    })
    return rows_data;
  })
```

再次，*步骤 4*、*5*和*6*中的代码在*第八章*中有详细解释，*创建无代码数据分析/处理系统*。

1.  然后我们调用`ReactTable`组件并传入`dataColumns`和`data`：

```js
<ReactTable
  data={data}
  columns={dataColumns}
  getTheadThProps={() => {
    return { style: { wordWrap: 'break-word', whiteSpace: 'initial' } }
  }}
  showPageJump={true}
  showPagination={true}
  defaultPageSize={10}
  showPageSizeOptions={true}
  minRows={10}
/>
```

`table`组件已完成；下一步是在 Next.js 中导入组件，然后调用该组件。

请注意，由于我们使用的是 Danfo.js 的 Web 版本，我们需要使用`next/dynamic`加载此组件，以防止应用程序崩溃：

```js
const Table = dynamic(
  () => import('../components/Table'),
  { ssr: false }
)
. . . . . . .
{typeof data != "undefined" && <Table dfData={data} username={user} />}
```

在上述代码中，我们动态导入了`Table`组件，并在内部实例化了`Table`组件，并传入了`dfData`和`username`的 prop 值。

如果您切换到浏览器并转到项目的`localhost`端口，您应该看到完整更新的应用程序，如下面的屏幕截图所示：

![图 12.7 - 提取的用户数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_07.jpg)

图 12.7 - 提取的用户数据

应用程序的最终结果应如下所示：

![图 12.8 - Twitter 用户仪表板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_12_08.jpg)

图 12.8 - Twitter 用户仪表板

在本节中，我们为前端实现构建了不同的组件。我们看到了如何在 Next.js 中使用 Danfo.js，还了解了如何使用`next/dynamic`加载组件。

# 总结

在本章中，我们看到了如何使用 Next.js 构建快速全栈应用程序。我们看到了如何在后端使用 Danfo.js 节点，还使用了 JavaScript 包，如 twit.js 和`nlp-node`来获取 Twitter 数据并进行情感分析。

我们还看到了如何轻松地将 Danfo.js 与 Next.js 结合使用，以及如何通过使用`next/dynamic`加载组件来防止错误。

本章的目标是让您看到如何轻松使用 Danfo.js 构建全栈（后端和前端）数据驱动应用程序，我相信本章在这方面取得了很好的成就。

我相信我们在本书中涵盖了很多内容，从介绍 Danfo.js 到使用 Danfo.js 构建无代码环境，再到构建推荐系统和 Twitter 分析仪表板。通过在各种 JavaScript 框架中使用 Danfo.js 的各种用例，我们能够构建分析平台和机器学习驱动的 Web 应用程序。

我们已经完成了本书的学习，我相信我们现在已经具备了在下一个 Web 应用程序中包含数据分析和机器学习的技能，并且可以为 Danfo.js 做出贡献。
