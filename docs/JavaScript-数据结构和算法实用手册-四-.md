# JavaScript 数据结构和算法实用手册（四）

> 原文：[`zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541`](https://zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：排序及其应用

排序是我们用来重新排列一组数字或对象以升序或降序排列的非常常见的算法。排序的更技术性的定义如下：

在计算机科学中，排序算法是一种将列表中的元素按照特定顺序排列的算法。

现在，假设您有一个包含*n*个项目的列表，并且您想对它们进行排序。您取出所有*n*个项目，并确定您可以将这些项目放置在所有可能的序列中，这种情况下总共有`n!`种可能。我们现在需要确定这些`n!`序列中哪些没有任何倒置对，以找出排序后的列表。倒置对被定义为列表中位置由`i，j`表示的一对元素，其中`i < j`，但值`x[i] > x[j]`。

当然，上述方法是繁琐的，需要一些繁重的计算。在本章中，我们将讨论以下主题：

+   排序算法的类型

+   为图书管理系统（如图书馆）创建 API

+   插入排序算法用于对书籍数据进行排序

+   归并排序算法用于对书籍数据进行排序

+   快速排序算法用于对书籍数据进行排序

+   不同排序算法的性能比较

让我们看一下上面列出的一些更优化的排序类型，可以在各种场景中使用。

# 排序算法的类型

我们都知道有不同类型的排序算法，大多数人在编程生涯中的某个时候都听说过这些不同类型的算法的名称。排序算法和数据结构之间的主要区别在于，无论使用哪种类型的算法，前者总是有相同的目标。这使得我们非常容易和重要地在各个方面比较不同的排序算法，大多数情况下都归结为速度和内存使用。在选择特定的排序算法之前，我们需要在手头的数据类型基础上做出这一决定。

考虑到以上情况，我们将比较和对比以下三种不同类型的算法：

+   插入排序

+   归并排序

+   快速排序

归并排序和快速排序是 v8 引擎在内部用于对数据进行排序的算法；当数据集大小太小（<10）时，使用归并排序，否则使用快速排序。另一方面，插入排序是一种更简单的算法。

然而，在我们深入讨论每种排序算法的实现之前，让我们快速看一下用例，然后设置相同的先决条件。

# 不同排序算法的用例

为了测试不同的排序算法，我们将创建一个小型的 express 服务器，其中将包含一个端点，用于获取按每本书的页数排序的所有书籍列表。在这个例子中，我们将从一个 JSON 文件开始，其中包含一个无序的书籍列表，这将作为我们的数据存储。

在生产应用中，排序应该推迟到数据库查询，并且不应作为应用逻辑的一部分来完成，以避免在处理筛选和分页请求等场景时出现痛苦和混乱。

# 创建一个 Express 服务器

我们设置项目的第一步是创建一个目录，我们想要在其中编写我们的应用程序；为此，在终端中运行以下命令：

```js
mkdir sorting
```

创建后，通过运行`cd`进入目录，然后运行 npm 初始化命令将其设置为 Node.js 项目：

```js
cd sorting
npm init
```

这将询问您一系列问题，您可以回答或留空以获得默认答案，两者都可以。项目初始化后，添加以下 npm 包，如前几章所做，以帮助我们设置 express 服务器：

```js
npm install express --save
```

添加后，我们现在准备创建我们的服务器。在项目的根目录中添加以下代码到一个新文件中，并将其命名为`index.js`：

```js
var express = require('express');
var app = express();

app.get('/', function (req, res) {
   res.status(200).send('OK!')
});

app.listen(3000, function () {
   console.log('Chat Application listening on port 3000!')
});
```

我们已经设置了一个返回`OK`的单个端点，并且我们的服务器正在端口`3000`上运行。让我们还在`package.json`文件的脚本中添加一个快捷方式来轻松启动应用程序：

```js
...
"scripts": {
  "start": "node index.js",
  "test": "echo \"Error: no test specified\" && exit 1" },
...
```

现在，要测试这些更改，请从根文件夹运行`npm start`，并在浏览器中打开`localhost:3000`。您应该在屏幕上看到一个`OK!`消息，如我们在`index.js`文件中定义的那样。

# 模拟图书馆书籍数据

现在，让我们创建我们的图书馆书籍的模拟数据，当用户请求书籍列表时，我们希望对其进行排序和返回。在本章中，我们将专注于按每本书的页数对图书馆书籍进行排序，因此我们只能简单地添加页数和书籍的 ID，如下面的代码所示：

```js
[
{"id":"dfa6cccd-d78b-4ea0-b447-abe7d6440180","pages":1133},
{"id":"0a2b0a9e-5b3d-4072-ad23-92afcc335c11","pages":708},
{"id":"e1a58d73-3bd2-4a3a-9f29-6cfb9f7a0007","pages":726},
{"id":"5edf9d36-9b5d-4d1f-9a5a-837ad9b73fe9","pages":1731},
...
]
```

我们想测试每个算法的性能，因此让我们添加 5000 本书，以确保我们有足够的数据来测试性能。此外，我们将在 300 到 2000 页之间随机添加这些页数，由于我们总共有 5000 本书，因此在不同的书籍中将会有明显的页数重复。

以下是一个示例脚本，您可以使用它来生成这些数据，如果您想使用此脚本，请确保安装了`uuid` npm 模块：

```js
npm install uuid --save
```

还要在项目的根目录创建一个名为`generator.js`的文件，并添加以下代码：

```js
const fs = require('fs');
const uuid = require('uuid');
const books = [];

for(var i = 0; i < 5000; i++) {
   books.push({
      "id": uuid.v4(),
      "pages": Math.floor(Math.random() * (2000 - 300 + 1) + 300)
   })
}

fs.writeFile('books.json', JSON.stringify(books), (err) => {});
```

现在，要运行它，请从根目录运行`node generator.js`命令，这将生成与前面代码中显示的记录类似的数据的`books.json`文件。

# 插入排序 API

现在，让我们创建一个端点，使用插入排序来根据页面计数对数据进行排序和返回。

# 什么是插入排序

插入排序，顾名思义，是一种排序类型，我们从输入数据集中逐个提取元素，然后确定元素应该放置的位置后，将它们插入到排序好的结果数据集中。

我们可以立即确定这种方法将需要额外的集合（与输入相同大小）来保存结果。因此，如果我们有一个包含 10 个元素的`Set`作为输入，我们将需要另一个大小也为 10 的`Set`作为输出。我们可以稍微改变这种方法，使我们的排序在内存中进行。在内存中执行操作意味着我们不会请求更多的内存（通过创建与输入相同大小的额外集合）。

# 伪代码

让我们快速勾画一下插入排序的伪代码：

```js
LOOP over all data excluding first entry (i = 1)

    INITIALIZE variable j = i - 1

    COPY data at index i

    WHILE all previous values are less than current

        COPY previous value to next

        DECREMENT j

    ADD current data to new position

RETURN sorted data
```

# 实现插入排序 API

根据前面描述的伪代码，实现插入排序非常容易。让我们首先创建一个名为`sort`的文件夹，然后创建一个名为`insertion.js`的文件，在其中我们将添加我们的插入类，如下面的代码所示：

```js
class Insertion {

   sort(data) {
      // loop over all the entries excluding the first record
  for (var i = 1; i< data.length; ++i) {

         // take each entry
  var current = data[i];

         // previous entry
  var j = i-1;

         // until beginning or until previous data is lesser than
         current
  while (j >= 0 && data[j].pages < current.pages) {

            // shift entries to right
  data[j + 1] = data[j];

            // decrement position for next iteration
  j = j - 1;
         }

         // push current data to new position
  data[j+1] = current;
      }

      // return all sorted data
  return data;
   }
}

module.exports = Insertion;
```

如伪代码和实际实现中所讨论的，我们将取每个值并将其与之前的值进行比较，当您有 5000 个随机顺序的项目时，这听起来并不是一件好事；这是真的，插入排序只有在数据集几乎排序并且整个数据集中有一些倒置对时才是首选。

改进此功能的一种方法是改变我们确定要在排序列表中插入的位置的方式。我们可以不再将其与所有先前的值进行比较，而是执行二进制搜索来确定数据应该移动到排序列表中的位置。因此，通过稍微修改前面的代码，我们得到以下结果：

```js
class Insertion {

   sort(data) {
      // loop over all the entries
  for (var i = 1; i < data.length; ++i) {

         // take each entry
  var current = data[i];

         // previous entry
  var j = i - 1;

         // find location where selected sould be inseretd
  var index = this.binarySearch(data, current, 0, j);

         // shift all elements until new position
  while (j >= index) {
            // shift entries to right
  data[j + 1] = data[j];

            // decrement position for next iteration
  j = j - 1;
         }

         // push current data to new position
  data[j + 1] = current;
      }

      // return all sorted data
  return data;
   }

   binarySearch(data, current, lowPos, highPos) {
      // get middle position
  var midPos = Math.floor((lowPos + highPos) / 2);

      // if high < low return low position;
 // happens at the beginning of the data set  if (highPos <= lowPos) {

         // invert condition to reverse sorting
  return (current.pages < data[lowPos].pages) ? (lowPos + 1):
         lowPos;
      }

      // if equal, give next available position
  if(current.pages === data[midPos].pages) {
         return midPos + 1;
      }

      // if current page count is less than mid position page count,
 // reevaluate for left half of selected range // invert condition and exchange return statements to reverse
      sorting  if(current.pages > data[midPos].pages) {
         return this.binarySearch(data, current, lowPos, midPos - 1);
      }

      // evaluate for right half of selected range
  return this.binarySearch(data, current, midPos + 1, highPos);
   }
}

module.exports = Insertion;
```

一旦实现，我们现在需要定义在我们的数据集上使用此排序的路由。为此，首先我们将导入之前创建的 JSON 数据，然后在我们的端点中使用它，我们专门创建它来使用插入排序对数据进行排序：

```js
var express = require('express');
var app = express();
var data = require('./books.json');
var Insertion = require('./sort/insertion');

app.get('/', function (req, res) {
   res.status(200).send('OK!')
});

app.get('/insertion', function (req, res) {
 res.status(200).send(new Insertion().sort(data));
});

app.listen(3000, function () {
   console.log('Chat Application listening on port 3000!')
});
```

现在，我们可以重新启动服务器，并尝试在浏览器或 postman 中访问`localhost:3000/insertion`端点，如下截图所示，以查看包含排序数据的响应：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/37231e17-b848-4451-b0a8-15d945bda797.png)

# 归并排序 API

现在，让我们创建一个端点，使用 Mergesort 对基于页面计数的数据进行排序并返回。

# 什么是 Mergesort

Mergesort 是一种分而治之的排序算法，首先将整个数据集划分为每个元素一个子集，然后重复地将这些子集连接和排序，直到得到一个排序好的集合。

这个算法同时使用了递归和分而治之的方法。让我们来看看这种实现的伪代码。

# 伪代码

根据我们迄今为止对 mergesort 的了解，我们可以得出实现的伪代码，如下所示：

```js
MERGE_SORT(array)
    INITIALIZE middle, left_half, right_half

    RETURN MERGE(MERGE_SORT(left_half), MERGE_SORT(right_half))

MERGE(left, right)

    INITIALIZE response

    WHILE left and right exist 

        IF left[0] < right[0]

            INSERT left[0] in result

        ELSE

            INSERT right[0] in result

    RETURN result concatenated with remainder of left and right
```

请注意，在前面的代码中，我们首先递归地将输入数据集划分，然后对数据集进行排序和合并。现在，让我们实现这个排序算法。

# 实现 Mergesort API

现在，让我们创建我们的 Mergesort 类，以及之前创建的 Insertionsort 类，并将其命名为`merge.js`：

```js
class Merge {

   sort(data) {
      // when divided to single elements
  if(data.length === 1) {
         return data;
      }

      // get middle index
  const middle = Math.floor(data.length / 2);

      // left half
  const left = data.slice(0, middle);

      // right half
  const right = data.slice(middle);

      // sort and merge
  return this.merge(this.sort(left), this.sort(right));
   }

   merge(left, right) {
      // initialize result
  const result = [];

      // while data
  while(left.length && right.length) {

         // sort and add to result
 // change to invert sorting  if(left[0].pages > right[0].pages) {
            result.push(left.shift());
         } else {
            result.push(right.shift());
         }
      }

      // concat remaining elements with result
  return result.concat(left, right);
   }
}

module.exports = Merge;
```

一旦我们有了这个类，我们现在可以添加一个新的端点来使用这个类：

```js
var express = require('express');
var app = express();
var data = require('./books.json');
var Insertion = require('./sort/insertion');
var Merge = require('./sort/merge');

app.get('/', function (req, res) {
   res.status(200).send('OK!')
});

app.get('/insertion', function (req, res) {
   res.status(200).send(new Insertion().sort(data));
});

app.get('/merge', function (req, res) {
 res.status(200).send(new Merge().sort(data));
});

app.listen(3000, function () {
   console.log('Chat Application listening on port 3000!')
});
```

现在重新启动服务器并测试所做的更改：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/7933b749-866e-43ec-bdde-05cfb564cf67.png)

# Quicksort API

与 Mergesort 类似，Quicksort 也是一种分而治之的算法。在本节中，我们将创建一个端点，使用这个算法对数据集进行排序并返回。

# 什么是 Quicksort

Quicksort 根据预先选择的枢轴值将集合分为两个较小的低值和高值子集，然后递归地对这些较小的子集进行排序。

选择枢轴值可以通过几种方式完成，这是算法中最重要的方面。一种方法是简单地从集合中选择第一个、最后一个或中间值。然后，还有自定义的分区方案，如 Lomuto 或 Hoare（我们将在本章后面使用），可以用来实现相同的效果。我们将在本节中探讨其中一些实现。

让我们来看看这个实现的伪代码。

# 伪代码

根据我们迄今为止讨论的内容，quicksort 的伪代码非常明显：

```js
QUICKSORT(Set, lo, high)

    GET pivot

    GENERATE Left, Right partitions

    QUICKSORT(SET, lo, Left - 1)

    QUICKSORT(SET, Right + 1, high)
```

正如您在前面的代码中所注意到的，一旦我们抽象出获取枢轴的逻辑，算法就不是很复杂。

# 实现 Quicksort API

首先，让我们创建 Quicksort 类，它将根据传递的集合中的第一个元素作为枢轴来对元素进行排序。让我们在`sort`文件夹下创建一个名为`quick.js`的文件：

```js
class Quick {

   simpleSort(data) {

      // if only one element exists
  if(data.length < 2) {
         return data;
      }

      // first data point is the pivot
  const pivot = data[0];

      // initialize low and high values
  const low = [];
      const high = [];

      // compare against pivot and add to
 // low or high values  for(var i = 1; i < data.length; i++) {

         // interchange condition to reverse sorting
  if(data[i].pages > pivot.pages) {
            low.push(data[i]);
         } else {
            high.push(data[i]);
         }
      }

      // recursively sort and concat the
 // low values, pivot and high values  return this.simpleSort(low)
         .concat(pivot, this.simpleSort(high));
   }

}

module.exports = Quick;
```

这很直接了当，现在，让我们快速添加一个端点来访问这个算法，对我们的书进行排序并将它们返回给请求的用户：

```js
var express = require('express');
var app = express();
var data = require('./books.json');
var Insertion = require('./sort/insertion');
var Merge = require('./sort/merge');
var Quick = require('./sort/quick');

....

app.get('/quick', function (req, res) {
 res.status(200).send(new Quick().simpleSort(data));
});

app.listen(3000, function () {
   console.log('Chat Application listening on port 3000!')
});
```

此外，现在重新启动服务器以访问新创建的端点。我们可以看到这里的方法并不理想，因为它需要额外的内存来包含低值和高值，与枢轴相比。

因此，我们可以使用之前讨论过的 Lomuto 或 Hoare 分区方案来在内存中执行此操作，并减少内存成本。

# Lomuto 分区方案

Lomuto 分区方案与我们之前实现的简单排序函数非常相似。不同之处在于，一旦我们选择最后一个元素作为枢轴，我们需要通过在内存中对元素进行排序和交换来不断调整其位置，如下面的代码所示：

```js
partitionLomuto(data, low, high) {

   // Take pivot as the high value
  var pivot = high;

   // initialize loop pointer variable
  var i = low;

   // loop over all values except the last (pivot)
  for(var j = low; j < high - 1; j++) {

      // if value greater than pivot
  if (data[j].pages >= data[pivot].pages) {

         // swap data
  this.swap(data, i , j);

         // increment pointer
  i++;
      }
   }

   // final swap to place pivot at correct
 // position by swapping  this.swap(data, i, j);

   // return pivot position
  return i;
}
```

例如，让我们考虑以下数据：

```js
[{pages: 20}, {pages: 10}, {pages: 1}, {pages: 5}, {pages: 3}]
```

当我们使用这个数据集调用我们的 partition 时，我们的枢轴首先是最后一个元素`3`（表示`pages: 3`），低值为 0（所以是我们的指针），高值为 4（最后一个元素的索引）。

现在，在第一次迭代中，我们看到第`j`个元素的值大于枢轴，所以我们将第`j`个值与低当前指针位置交换；由于它们两者相同，交换时什么也不会发生，但我们会增加指针。因此，数据集保持不变：

```js
20, 10, 1, 5, 3
pointer: 1
```

在下一次迭代中，同样的事情发生了：

```js
20, 10, 1, 5, 3
pointer: 2
```

在第三次迭代中，值较小，所以什么也不会发生，循环继续：

```js
20, 10, 1, 5, 3
pointer: 2
```

在第四次迭代中，值（`5`）大于枢轴值，所以值交换并且指针增加：

```js
20, 10, 5, 1, 3
pointer: 3
```

现在，控制权从`for`循环中退出，我们最终通过最后一次交换将数据放在正确的位置，得到以下结果：

```js
20, 10, 5, 3, 1 
```

之后，我们可以返回指针的位置，这只是枢轴的新位置。在这个例子中，数据在第一次迭代中就已经排序，但可能会有情况，也会有情况，其中不是这样，因此我们递归地重复这个过程，对枢轴位置左右的子集进行排序。

# 霍尔分区方案

另一方面，霍尔分区方案从数据集的中间获取一个枢轴值，然后开始解析从低端和高端确定枢轴的实际位置；与 Lomuto 方案相比，这会导致更少的操作次数：

```js
partitionHoare(data, low, high) {
   // determine mid point
  var pivot = Math.floor((low + high) / 2 );

   // while both ends do not converge
  while(low <= high) {

      // increment low index until condition matches
  while(data[low].pages > data[pivot].pages) {
         low++;
      }

      // decrement high index until condition matches
  while(data[high] && (data[high].pages < data[pivot].pages)) {
         high--;
      }

      // if not converged, swap and increment/decrement indices
  if (low <= high) {
         this.swap(data, low, high);
         low++;
         high--;
      }
   }

   // return the smaller value
  return low;
}
```

现在，我们可以将所有这些放入我们的`Quick`类中，并更新我们的 API 以使用新创建的方法，如下面的代码所示：

```js
class Quick {

   simpleSort(data) {
        ...
   }

   // sort class, default the values of high, low and sort
   sort(data, low = 0, high = data.length - 1, sort = 'hoare') {
      // get the pivot   var pivot =  (sort === 'hoare') ? this.partitionHoare(data, low,
      high)
                  : this.partitionLomuto(data, low, high);

      // sort values lesser than pivot position recursively
  if(low < pivot - 1) {
         this.sort(data, low, pivot - 1);
      }

      // sort values greater than pivot position recursively
  if(high > pivot) {
         this.sort(data, pivot, high);
      }

      // return sorted data
  return data;
   }

   // Hoare Partition Scheme
  partitionHoare(data, low, high) {
        ...
   }

   // Lomuto Partition Scheme
  partitionLomuto(data, low, high) {
        ...
   }

   // swap data at two indices
  swap(data, i, j) {
      var temp = data[i];
      data[i] = data[j];
      data[j] = temp;
   }

}

module.exports = Quick;
```

当我们更新 API 调用签名时，在我们的`index.js`文件中得到以下结果：

```js
app.get('/quick', function (req, res) {
 res.status(200).send(new Quick().sort(data));
});
```

重新启动服务器并访问端点后，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/19f51739-0563-46d2-bbe3-db4a92dce4ce.png)

从前面的截图中可以看出，对于给定的数据集，快速排序比归并排序稍微快一些。

# 性能比较

现在我们列出并实现了一些排序算法，让我们快速看一下它们的性能。在我们实现这些算法时，我们简要讨论了一些性能增强；我们将尝试量化这种性能增强。

为此，我们将首先安装名为`benchmark`的节点模块，以创建我们的测试套件：

```js
npm install benchmark --save
```

安装了基准框架后，我们可以将我们的测试添加到项目根目录下的名为`benchmark.js`的文件中，该文件将运行前面部分描述的不同排序算法：

```js
var Benchmark = require('benchmark');
var suite = new Benchmark.Suite();
var Insertion = require('./sort/insertion');
var Merge = require('./sort/merge');
var Quick = require('./sort/quick');
var data = require('./books.json');

suite
  .add('Binary Insertionsort', function(){
      new Insertion().sort(data);
   })
   .add('Mergesort', function(){
      new Merge().sort(data);
   })
   .add('Quicksort -> Simple', function(){
      new Quick().simpleSort(data);
   })
   .add('Quicksort -> Lomuto', function(){
      new Quick().sort(data, undefined, undefined, 'lomuto');
   })
   .add('Quicksort -> Hoare', function(){
      new Quick().sort(data);
   })
   .on('cycle', function(e) {
      console.log(`${e.target}`);
   })
   .on('complete', function() {
      console.log(`Fastest is ${this.filter('fastest').map('name')}`);
   })
   .run({ 'async': true });
```

现在，让我们更新`package.json`文件的脚本标签以更新和运行测试：

```js
...

"scripts": {
  "start": "node index.js",
  "test": "node benchmark.js" },

...
```

要查看更改，请从项目的根目录运行`npm run test`命令，我们将在终端中看到类似的东西：

```js
Binary Insertionsort x 1,366 ops/sec ±1.54% (81 runs sampled)
Mergesort x 199 ops/sec ±1.34% (78 runs sampled)
Quicksort -> Simple x 2.33 ops/sec ±7.88% (10 runs sampled)
Quicksort -> Lomuto x 2,685 ops/sec ±0.66% (86 runs sampled)
Quicksort -> Hoare x 2,932 ops/sec ±0.67% (88 runs sampled)
Fastest is Quicksort -> Hoare
```

# 总结

排序是我们经常使用的东西。了解排序算法的工作原理以及根据数据集类型如何使用这些算法是很重要的。我们对基本方法进行了一些关键的改变，以确保我们优化了我们的算法，并最终得出了一些统计数据，以了解这些算法在相互比较时的效率如何。当然，有人可能会想到是否有必要进行性能测试来检查一个算法是否比另一个更好。我们将在接下来的章节中讨论这个问题。


# 第八章：大 O 符号、空间和时间复杂度

在前几章中，我们经常谈到优化我们的代码/算法，并简要使用了空间和时间复杂度这些术语，以及我们希望将它们降到最低。顾名思义，我们希望将代码的复杂性保持在最低，但这意味着什么？这种复杂性有不同的级别吗？我们如何计算算法的空间和时间复杂度？这些是我们将在本章讨论的问题，同时讨论以下主题：

+   不同程度的时间复杂度

+   空间复杂度和辅助空间

# 术语

讨论算法的空间和时间复杂度时使用的术语是开发人员经常会遇到的。流行的术语，如**大 O 符号**，也被称为**O（something）**，以及一些不那么流行的术语，如**Omega（something）**或**Theta（something）**经常用来描述算法的复杂性。O 实际上代表 Order，表示函数的阶数。

让我们首先只讨论算法的时间复杂度。基本上，这归结为我们试图弄清楚系统在给定数据集（D）上执行我们的算法需要多长时间。我们可以在所述系统上运行此算法并记录其性能，但由于并非所有系统都相同（例如，操作系统、处理器数量和读写速度），我们不能期望结果真正代表执行我们的算法所需的平均时间。同时，我们还需要知道我们的算法在数据集 D 的大小变化时的表现。它对于 10 个元素和 1000 个元素需要相同的时间吗？还是花费的时间呈指数增长？

有了上述所有内容，我们如何清楚地理解算法的复杂性呢？我们通过将算法分解为一组基本操作，然后将它们组合起来，得到每个操作的总体数量/复杂度。这真正定义了算法的时间复杂度，即随着输入数据集 D 的大小增长而增长的时间速率。

现在，为了以抽象的方式计算时间复杂度，让我们假设我们有一台机器，它需要一个单位的时间来执行一些基本操作，比如读取、写入、赋值、算术和逻辑计算。

说到这里，让我们来看一个简单的函数，它返回给定数字的平方：

```js
function square(num) {
    return num*num;
}
```

我们已经定义了我们的机器，它消耗一个单位的时间来执行乘法，另一个单位来返回结果。不考虑输入，我们的算法总是只需要 2 个单位的时间，因为这不会改变，所以被称为常数时间算法。这里所花费的常数时间是 k 个时间单位并不重要。我们可以将所有类似的函数表示为`O(1)`或`big-O(1)`的一组函数，这些函数执行需要恒定的时间。

让我们再举一个例子，我们循环遍历一个大小为 n 的列表，并将每个元素乘以一个因子：

```js
function double(array) {
    for(var i = 0; i <  array.length; i++) {
        array[i] *= 2;
    }

    return array;
}
```

要计算这个函数的时间复杂度，我们首先需要计算这个函数中每个语句的执行成本。

第一条语句在中断之前执行*n+1*次，并且每次执行时，增加 1 个单位的成本和进行比较检查等其他操作也需要 1 个单位的成本。换句话说，我们可以假设每次迭代中花费了*C*[1]个时间单位，因此下面这行代码的总成本是*C[1]*(n+1)*：

```js
for(var i = 0; i <  array.length; i++) {
```

在下一条语句中，我们将数组中给定索引处的值乘以 2。由于这是在循环内部，这条语句执行了 n 次，每次执行时，我们假设它花费了*C[2]*个单位。因此，这行代码的总执行成本将是*C[2]*n*：

```js
array[i] *= 2;
```

然后，我们最终有返回语句，它也需要花费一个常数的时间—*C[3]*—来将最终的数组返回给调用者。将所有这些成本加在一起，我们得到方法的总成本如下：

```js
Tdouble = C1*(n + 1) + C2* n + C3;
        = C5 * n + C4 // where C4 = C3 + C1 and C5 = C1 + C2
```

我们可以看到，在这种情况下，方法的成本与输入数组的大小`N`成正比。因此，这组函数可以用`O(n)`表示，表明它们与输入大小成正比。

然而，在我们跳到更多的例子之前，让我们先看看如何在没有所有计算的情况下表示复杂度。

# 渐近符号

当我们想要推导和比较两个或更多算法的时间复杂度时，渐近符号非常有用。渐近符号的意思是，一旦我们计算出一个算法的时间复杂度，我们只需要用一个非常大的数（趋向于无穷大）来替换*n*（我们算法的输入大小），然后去掉方程中的常数。这样做会让我们留下真正影响我们执行时间的唯一因素。

让我们拿和前面部分相同的例子：

```js
Tdouble = C1*(n + 1) + C2* n + C3;
        = C5 * n + C4 // where C4 = C3 + C1 and C5 = C1 + C2
```

当我们应用刚刚描述的关于渐近符号的规则时，即*n -> 无穷大*，我们很快就能看到`C[4]`的影响相当微不足道，可以忽略不计。我们也可以说相同的事情适用于乘法因子`C[5]`。我们得到的是这一次，`T[double]`与输入数组的大小`(n)`成正比，因此我们能够用`O(n)`符号表示这一点，因为在这种情况下，大小 n 是唯一重要的变量。

有三种主要类型的渐近符号，可以用来对算法的运行时间进行分类：

+   **Big-O**：表示运行时间增长率的上界

+   **Omega**：表示运行时间增长率的下界

+   **Theta**：表示运行时间增长率的紧密界限

# 大 O 符号

假设我们有一个`f(n)`方法，我们想用一个时间复杂度函数（即一个集合）`g(n)`来表示：

当且仅当存在常数 c 和 n[0]，使得`f(n) <= cg(n)`，且输入大小`n >= n[0]`时，`f(n)`是`O(g(n))`。

现在，让我们尝试将这个应用到我们之前的例子中：

```js
f(n) = Tdouble = C5 * n + C4 
f(n) = Tdouble = 4n + 1 // cause C5 and C4 can be any constants
```

对于这个例子，我们用集合`O(n)`表示它，也就是`g(n) = n`。

为了使我们的时间复杂度断言成立，我们需要满足以下条件：

```js
4n + 1 <= c * n , where n >= n0
```

这个方程对于`c = 5`和`n[0] = 1`的值是满足的。另外，由于定义得到满足，我们可以安全地说`f(n)`函数是`big-O(g(n))`，也就是`O(g(n))`，或者在这种情况下是`O(n)`。我们也可以在图表上看到这一点，如下图所示；在`n = 1`之后，我们可以看到`c * g(n)`的值在渐近上始终大于`f(n)`的值。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/bf044bdb-d2b6-4447-b244-932702ba8e11.png)

# Omega 符号

类似于之前讨论的大 O 符号，Omega 符号表示算法运行时间的增长率的下界。因此，如果我们有一个`f(n)`方法，我们想用一个时间复杂度函数（即一个集合）`g(n)`来表示，那么 Omega 符号可以定义如下：

当且仅当存在常数 c 和 n[0]，使得`f(n) >= cg(n)`，其中输入大小`n >= n[0]`时，`f(n)`是`O(g(n))`。

采用和前面部分相同的例子，我们有`f(n) = 4n + 1`，然后`g(n) = n`。我们需要验证存在 c 和 n[0]，使得前面的条件成立，如下面的片段所示：

```js
4n + 1 >= c * n , where n >= n0 
```

我们可以看到这个条件对于`c = 4`和`n[0] = 0`是成立的。因此，我们可以说我们的函数`f(n)`是`Ω(n)`。我们也可以在图表上表示这一点，看一下它如何表示我们的函数`f(n)`以及它的上界和下界：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/70c13bfd-ef7e-4149-bf2f-c75c67e23ac2.png)

从前面的图表中，我们可以看到我们的函数`f(n)`（黑色）位于渐近上限和下限（灰色）之间。*x*轴表示大小（*n*）的值。

# θ符号

计算了函数`f(n)`的增长率的上限和下限之后，我们现在也可以确定函数`f(n)`的紧密边界或θ。因此，如果我们有一个`f(n)`方法，我们想用时间复杂度函数（也称为集合）`g(n)`来表示，那么函数的紧密边界可以定义如下：

如果`f(n)`是 O(g(n))，当且仅当存在常数 c 和 n[0]，使得 c[1]g(n) <= f(n) <= c[2]g(n)，其中输入大小 n >= n[0]

前两节的操作已经计算了我们的函数，即`f(n) = 4n + 1`：`c[1] = 4`，`c[2] = 5`，`n[0] = 1`。

这为我们提供了函数`f(n)`的紧密边界，由于函数始终在`n = 1`之后的紧密边界内，我们可以安全地说我们的函数 f(n)具有紧密的增长率，即`θ(n)`。

# 回顾

在继续下一个主题之前，让我们快速回顾一下我们讨论的不同类型的符号：

+   `O`表示`f(n)`的增长率渐近小于或等于*g(n)*的增长率

+   `Ω`表示`f(n)`的增长率渐近大于或等于*g(n)*的增长率

+   `θ`表示`f(n)`的增长率渐近等于`g(n)`的增长率

# 时间复杂度的例子

现在让我们检查一些时间复杂度计算的例子，因为在 99%的情况下，我们需要知道函数可能执行的最长时间；我们将主要分析最坏情况时间复杂度，即基于函数输入的增长率的上限。

# 常数时间

常数时间函数是指执行时间不受传入函数的大小的影响：

```js
function square(num) {
    return num*num;
}
```

前面的代码片段是一个常数时间函数的例子，用 O(1)表示。常数时间算法是最受追捧的算法，因为它们无论输入的大小如何都在恒定时间内运行。

# 对数时间

对数时间函数是指执行时间与输入大小的对数成比例。考虑以下例子：

```js
for(var i = 1; i < N; i *= 2) {
    // O(1) operations
}
```

我们可以看到，在任何给定的迭代中，*i = 2^i*，因此在第*n*次迭代中，*i = 2^n*。此外，我们知道*i*的值始终小于循环本身的大小(*N*)。由此，我们可以推断出以下结果：

```js
2n < N

log(2n) < log(N)

n < log(N) 
```

从前面的代码中，我们可以看到迭代次数始终小于输入大小的对数。因此，这样的算法的最坏情况时间复杂度将是`O(log(n))`。

让我们考虑另一个例子，下一次迭代将`i`的值减半：

```js
for(var i = N; i >= 1; i /= 2) {
    // O(1) operations
}
```

在第`n`次迭代中，`i`的值将为`N/2^n`，我们知道循环以值`1`结束。因此，为了使循环停止，`i`的值需要`<= 1`；现在，通过结合这两个条件，我们得到以下结果：

```js
N/2n <= 1

N <= 2n

Log(N) <= n
```

我们可以得出与第一个例子类似的结论，即迭代次数始终小于输入大小或值的对数值。

需要注意的一点是，这不仅限于加倍或减半现象。这可以应用于任何算法，其中步骤的数量被因子`k`减少。这类算法的最坏情况时间复杂度将是`O(logk)`，在我们的前面的例子中，`k`恰好是`2`。

对数时间复杂度算法是下一个受欢迎的，因为它们以对数方式消耗时间。即使输入的大小翻倍，算法的运行时间也只会增加一个小的数（这是对数的定义）。

# 线性时间

现在让我们讨论最常见的时间复杂度之一，线性时间。可以猜到，方法的线性时间复杂度表示该方法执行需要线性时间：

```js
for(var i = 0; i < N; i += c) {
    // O(1) operations
}
```

这是一个非常基本的`for`循环，我们在其中执行一些常数时间的操作。随着 N 的大小增加，循环执行的次数也会增加。

正如你所看到的，在每次迭代中，`i`的值都会增加一个常数`c`，而不是`1`。这是因为增量是什么并不重要，只要它们是线性的。

在第一次迭代中，`i = 0`；在第二次迭代中，`i = c`，然后在第三次迭代中是`c + c = 2c`，在第四次迭代中是`3c`，依此类推。因此，在第 n 次迭代中，我们有`i = c(n-1)`的值，渐近地是`O(n)`。

根据你的用例是什么，线性时间复杂度可能是好的，也可能不是。这有点是灰色地带，如果你不确定是否需要进一步优化，有时可能会放弃。

# 二次时间

随着二次时间复杂度算法，我们现在进入了时间复杂度的黑暗面。顾名思义，输入的大小会二次影响算法的运行时间。一个常见的例子是嵌套循环：

```js
for (int i = 0; i <n; i += c) {
    for (int j = 0; j < n; j += c) {
        // some O(1) expressions
    }
}
```

正如前面的例子所示，对于`i = 0`，内部循环运行*n*次，对于`i = 1`，`i = 2`，依此类推。内部循环总是运行 n 次，不依赖于 n 的值，因此使得算法的时间复杂度为`O(n²)`。

# 多项式时间

多项式时间复杂度是算法的运行时间复杂度，其顺序为`n^k`。二次时间复杂度算法是多项式时间算法的某种类型，其中`k = 2`。这样的算法的一个非常简单的例子如下：

```js
for (int i = 0; i <n; i += c) {
    for (int j = 0; j < n; j += c) {
        for (int k = 0; k < n; k += c) {
            // some O(1) expressions
        }
    }
}
```

正如你所看到的，这个例子只是二次时间部分例子的延伸。这种情况的最坏时间复杂度是`O(n³)`。

# 多项式时间复杂度类

现在我们已经开始了这个对话，到目前为止我们讨论的大部分时间复杂度类型都是`O(n^k)`类型的，例如，对于`n = 1`，它是常数时间复杂度，而对于`k = 2`，它是二次复杂度。

多项式时间复杂度的概念引导我们进入了一类问题，这些问题是根据其解决方案的复杂性定义的。以下是类别的类型：

+   **P**：任何可以在多项式时间`O(n^k)`内解决的问题。

+   **NP**：任何可以在多项式时间内验证的问题。可以存在可以在非确定性多项式时间内解决的问题（例如数独求解）。如果这些问题的解决方案可以在多项式时间内验证，那么问题被分类为 NP 类问题。NP 类问题是 P 类问题的超集。

+   **NP-Complete**：任何可以在多项式时间内减少为另一个 NP 问题的 NP 问题可以被分类为 NP-Complete 问题。这意味着如果我们知道某个**NP**问题的解决方案，那么可以在多项式时间内推导出另一个 NP 问题的解决方案。

+   **NP-Hard**：如果存在一个可以在多项式时间内减少为**NP-Complete**问题的**NP-Complete**问题，那么问题可以被分类为 NP-Hard 问题（H）。

在大多数现实场景中，我们会遇到很多 P 和 NP 问题，NP 类问题的一个经典例子是旅行推销员问题，其中推销员想要访问`n`个城市，从他的家出发并结束他的旅行。在汽油有限和总里程数有上限的情况下，推销员能否访问所有城市而不用完汽油？

# 递归和加法复杂度

到目前为止，我们已经看到一些相当简单的例子：它们都只有一个循环或嵌套循环。然而，很多时候，会有一些情况需要处理多个循环/函数调用/分支，让我们看一个这种情况下如何计算复杂度的例子？

1.  当我们有连续的循环/函数调用时，我们需要计算每个步骤的个体复杂度，然后将它们相加以获得总体复杂度，如下所示：

```js
            function xyz() {

                abc(); // O(n) operation

                pqr(); // O(log(n)) operation

            }
```

这段代码的综合复杂度将是两个部分复杂度的总和。因此，在这种情况下，总体复杂度将是`O(n + log n)`，渐近地将是`O(n)`。

1.  当我们的函数中有不同时间复杂度的分支时，根据我们所谈论的运行时复杂度的类型，我们需要选择正确的选择：

```js
        function xyz() {

            if (someCondition) {

                abc(); // O(n) operation

            } else {

                pqr(); // O(log(n)) operation

            }

        }
```

在这种情况下，最坏情况的复杂度将由两个分支中较差的那个决定，即`O(n)`，但最佳情况的复杂度将是`O(log(n))`。

1.  递归算法与非递归算法相比有点棘手，因为我们不仅需要确定算法的复杂度，还需要记住递归会触发多少次，因为这将对算法的总体复杂度产生影响，如下面的代码片段所示：

```js
        function rec1(array) {
            // O(1) operations

            if (array.length === 0) return;

            array.pop();

            return rec1(array);
        }
```

虽然我们的方法只执行一些`O(1)`的操作，但它不断改变输入并调用自身，直到输入数组的大小为零。因此，我们的方法最终执行了 n 次，使得总体时间复杂度为`O(n)`。

# 空间复杂度和辅助空间

空间复杂度和辅助空间是在谈论某个算法的空间复杂度时经常混淆和交替使用的术语之一：

+   **辅助空间：**算法暂时占用的额外空间以完成其工作

+   **空间复杂度：**空间复杂度是算法相对于输入大小所占用的总空间加上算法使用的辅助空间。

当我们尝试比较两个算法时，通常会有类似类型的输入，也就是说，输入的大小可以忽略不计，因此我们最终比较的是算法的辅助空间。使用这两个术语没有太大问题，只要我们理解两者之间的区别并正确使用它们。

如果我们使用低级语言如 C，那么我们可以根据数据类型来分解所需/消耗的内存，例如，用 2 个字节来存储整数，4 个字节来存储浮点数等。然而，由于我们使用的是 JavaScript 这种高级语言，情况就不那么简单了，因为我们没有明确区分不同的数据类型。

# 空间复杂度的例子

在谈论算法的空间复杂度时，我们有类似于时间复杂度的类型，如常量空间`S(1)`和线性空间`S(N)`。让我们在下一节中看一些例子。

# 常量空间

常量空间算法是指算法消耗的空间不会因输入的大小或算法的输入参数而改变。

在这一点上，我想重申一下，当我们谈论算法的空间复杂度时，我们谈论的是算法消耗的辅助空间。这意味着即使我们的数组大小为*n*，我们的算法消耗的辅助（或额外）空间将保持不变，如下面的代码片段所示：

```js
function firstElement(arr) {
    return arr[0];
}
```

我们可以看到`firstElement`方法不再占用任何空间，无论输入是什么。因此，我们可以将其表示为空间复杂度`S(1)`。

# 线性空间

线性空间算法是指算法占用的空间量与输入大小成正比的算法，例如，在返回值之前循环遍历数组并将值推送到新数组的算法：

```js
function redundant(array) {
    var result = [];

    for(var i = 0, i < array.size; i++) {
        result.push(array[i]);
    }

    return result;
}
```

如你所见，尽管冗余，我们正在创建一个新数组，并将所有值推送到该数组中，这将占用与输入数组相同的空间。考虑在`push`之前有一个条件的情况，如下面的代码所示：

```js
function notRedundant(array) {
    var result = [];

    for(var i = 0, i < array.size; i++) {
        if (someCondition) {
            result.push(array[i]);
        }
    }

    return result;
}
```

在最坏的情况下，`someCondition` 标志始终为真，并且我们最终得到的结果与输入的大小相同。因此，我们可以断言前面方法的空间复杂度为 `S(n)`。

# 总结

在本章中，我们只是浅尝计算复杂性这个庞然大物。计算复杂性比我们在本章讨论的要多得多。然而，本章讨论的主题和示例是我们大多数人在日常工作中面对的。空间复杂性还有更高级的主题，比如 LSPACE，它是一类可以在对数空间中解决的问题，以及 NLSPACE，它是使用非确定性图灵机的空间量。本章的主要目标是确保我们理解算法的复杂度是如何计算的，以及它如何影响整体输出。在下一章中，我们将讨论我们可以对应用程序进行哪些微观优化，并了解浏览器（主要是 Chrome）的内部工作原理以及我们如何利用它们来改进我们的应用程序。


# 第九章：微优化和内存管理

在本章中，我们将介绍 HTML、CSS、JavaScript 和我们期望所有这些内容在其中运行的浏览器的一些基本概念。我们一直以来都以某种风格编码，这是自然的。然而，我们是如何形成这种风格的？它是好的还是可以变得更好？我们如何决定我们应该和不应该要求其他人遵循什么？这些是我们将在本章中尝试回答的一些问题。

在本章中，我们将讨论以下内容：

+   最佳实践的重要性，以及一些示例。

+   探索不同类型的 HTML、CSS 和 JavaScript 优化

+   深入了解 Chrome 一些功能的内部工作。

# 最佳实践

出于明显的原因，最佳实践是一个相对的术语。什么被认为是最佳的，更多取决于你所在的团队以及你使用的 JavaScript 版本。在本节中，我们将尝试广泛涵盖一些最佳实践，并了解一些实践看起来是什么样子，以便我们也可以适应并使用它们。

# HTML 的最佳实践

让我们从上到下来处理 HTML 文件中每个部分的最佳实践。

# 声明正确的 DOCTYPE

你是否曾经想过为什么我们在页面顶部有`<!DOCTYPE html>`？我们显然可以不写它，页面似乎仍然可以工作。那么，我们为什么需要这个？答案是**避免向后兼容性**——如果我们不指定 DOCTYPE，解释和呈现我们的 HTML 的浏览器将进入怪癖模式，这是一种支持使用过时版本和标记的 HTML、CSS 和 JS 构建的非常旧的网站的技术。怪癖模式模拟了旧版本浏览器中存在的许多错误，我们不想处理这些错误。

# 向页面添加正确的元信息

任何网页在呈现时都需要一些元信息。虽然这些信息不会在页面上呈现，但对于正确呈现页面至关重要。以下是一些添加元信息的良好实践：

+   在`html`标签中添加正确的`lang`属性，以符合 w3c 的国际化标准：

```js
<html lang="en-US">
```

+   声明正确的`charset`以支持网页上的特殊字符：

```js
<meta charset="UTF-8">
```

+   添加正确的`title`和`description`标签以支持搜索引擎优化：

```js
<title>This is the page title</title>

<meta name="description" content="This is an example description.">
```

+   添加适当的`base` URL 以避免在各处提供绝对 URL：

```js
<base href="http://www.mywebsite.com" />
...
...
<img src="/cats.png" /> // relative to base 
```

# 删除不必要的属性

这可能看起来很明显，但仍然被广泛使用。当我们添加一个`link`标签来下载样式表时，我们的浏览器已经知道它是一个样式表。没有理由指定该链接的类型：

```js
<link rel="stylesheet" href="somestyles.css" type="text/css" />
```

# 使您的应用程序适用于移动设备

你是否曾经见过那些在桌面和移动设备上看起来完全相同的网站，并想知道为什么他们要这样构建？在新时代的网页开发中，为什么有人不利用最新的 HTML 和 CSS 版本提供的响应性？这可能发生在任何人身上；我们已经定义了所有正确的断点，并且按预期使用媒体查询，但什么都没有发生。这通常是因为我们忘记了包括`viewport`，`meta`标签；包括`viewport`的`meta`标签可以解决我们所有的问题：

```js
<meta name="viewport" content="width=device-width, initial-scale=1">
```

“视口”基本上是用户可见区域的总和，在移动设备上较小，在桌面上较大；`meta`标签定义了浏览器根据“视口”的大小来呈现网站的方式。

# 在<head>中加载样式表

这是一个偏好和选择的问题。我们可以在页面加载的末尾加载样式表吗？当然可以，但我们希望避免这样做，以便我们的用户在捕捉到正确的样式之前不会看到未经样式化的页面闪烁。当浏览器提供 CSS 和 HTML 时，它们创建一个**CSS 对象模型**（**CSSOM**）和**文档对象模型**（**DOM**）。在构建 DOM 时，浏览器查找 CSSOM，以检查是否有任何与 DOM 节点对应的样式。因此，我们希望确保 CSSOM 已经构建并准备好供 DOM 渲染。

一个替代方法是首先在页面的头部标签中只加载基本样式，其余的样式可以在 body 的末尾请求。这意味着我们的页面可以渲染得更快一些，但值得注意的是，这有时可能不值得，这取决于您的应用程序大小和用例。

# 避免内联样式

通过在 HTML 文件中直接提供内联样式来使用它们是不好的，原因有很多：

+   我们无法重用应用于一个元素的样式

+   我们的 HTML 充斥着 CSS，变得非常嘈杂

+   我们无法利用伪元素，比如`before`和`after`

# 使用语义标记

有了 HTML5，我们不再需要担心为所有内容使用`<div>`标签。我们得到了一组更强大的语义标签，这些标签帮助我们以更有意义的方式构建我们的模板：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/dd8cb81c-7052-4a20-afb6-c694e977c20d.png)值得注意的是，这些新标签只为我们的模板提供了含义，而没有样式。如果我们希望它看起来某种方式，我们需要根据我们希望它们看起来的样子来设计元素。此外，新的 HTML5 标签在 IE9 之前的浏览器中不可用，因此我们需要准备一些备用方案，如 HTML5shiv。

# 使用可访问的丰富互联网应用程序（ARIA）属性

每当我们开发一个网络应用程序时，我们都需要确保我们的应用程序与屏幕阅读器兼容，以支持残障用户：

```js
<div id="elem" aria-live="assertive" role="alert" aria-hidden="false"> An error occurred </div>
```

这些信息不会与屏幕上的任何现有信息发生冲突，并且使屏幕阅读器能够捕捉和处理这些信息。当然，只有在 HTML 渲染器支持 ARIA 时，所有这些才是可能的，这在所有最新的浏览器中都是可用的。

# 在末尾加载脚本

任何应用程序的核心都存在于开发人员定义的 JavaScript 文件中。因此，当我们尝试加载和执行这些文件时，我们需要格外注意，因为它们的大小可能比它们的 HTML 和 CSS 文件的大小要大得多。当我们尝试使用脚本标签加载外部 JS 文件时，浏览器首先下载然后执行它们（在解析和编译之后）。我们需要确保我们的应用程序在正确的时间加载和执行。对我们来说，这意味着如果我们的应用逻辑依赖于 DOM，我们需要确保 DOM 在脚本执行之前被渲染。这就是为什么我们需要在应用程序的 body 标签末尾加载脚本的一个很好的理由。

即使我们的 JavaScript 不依赖于 DOM，我们仍然希望在末尾加载我们的脚本，因为脚本标签默认是渲染阻塞的，也就是说，如果您的浏览器在头部（例如）遇到您的脚本标签，它开始下载和执行 JS 文件，并且在执行完成之前不渲染页面的其余部分。此外，如果我们有太多的 JS 文件，那么页面似乎已经挂起，并且在所有 JS 文件都已成功下载和执行之前，不会完全渲染 UI 给我们的最终用户。

如果您仍然希望添加脚本标签以及链接标签以下载样式表，则有一个解决方法。您可以向脚本标签添加`defer`或`async`属性。`Defer`允许您在 DOM 渲染时并行下载文件，并在渲染完成后执行脚本。`async`在 DOM 渲染时并行下载文件，并在执行时暂停渲染，然后在执行后恢复。明智地使用它们。

# CSS 最佳实践

CSS 最佳实践的列表不像 HTML 那么长。此外，通过使用预处理语言，如**Sassy CSS**（**SCSS**），许多潜在问题可以得到显著缓解。假设由于某种原因您不能使用 SCSS，并讨论纯粹的 CSS 的优缺点。

# 避免内联样式

这足够重要，以至于成为 HTML 和 CSS 最佳实践的一部分。不要应用内联样式。

# 不要使用!important

说起来容易，做起来难。使用`!important`是使样式应用于元素的最简单的解决方法之一。然而，这也有其代价。CSS 或层叠样式表依赖于样式根据应用程序的优先级（ID、类和元素标签）或它们出现的顺序进行级联。使用`!important`会破坏这一点，如果您有多个 CSS 文件，那么纠正它将变得非常混乱。最好避免这样的做法，从一开始就用正确的方法做。

# 在类中按字母顺序排列样式

这听起来不像什么大不了的事，对吧？如果您只有一个带有几个类的 CSS 文件，那也许还可以。但是，当您有一个包含复杂层次结构的大文件时，您最不希望的是犯一个小错误，这会花费您大量的时间。看看以下示例：

```js
.my-class {
    background-image: url('some-image.jpg');
 background-position: 0 100px;
 background-repeat: no-repeat;
    height: 500px;
    width: 500px;
    ...
    ...
    margin: 20px;
    padding: 10px;
 background: red;
}
```

请注意，在上述代码中，我们为元素的背景属性添加了冲突的样式，现在在渲染时，它全部是红色的。这本来很容易被发现，但由于类内属性的顺序，它被忽略了。

# 按升序定义媒体查询

定义媒体查询是另一个随着应用程序规模增长而变得混乱的领域。在定义媒体查询时，始终按递增顺序定义它们，以便您可以隔离您的样式并留下一个开放的上限，如下所示：

```js
...

Mobile specific styles

...  // if screen size is greater than a small mobile phone
@media only screen and (min-width : 320px)  { // overrides which apply }   // if screen size is greater than a small mobile phone in portrait mode // or if screen size is that of a tablet @media only screen and (min-width : 480px)  { // overrides that apply }  // if screen size is greater than a tablet  @media only screen and (min-width : 768px)  { 
    // overrides that apply }   // large screens @media only screen and (min-width : 992px)  { ... }   // extra large screens and everything above it @media only screen and (min-width : 1200px)  { ... }
```

请注意，在上述代码中，我们将最后一个媒体查询留给了适用于所有屏幕尺寸为`1200px`及以上的情况，这将涵盖显示器、电视等。如果我们按照屏幕尺寸的最大宽度设置样式，那么这样做就不会奏效。如果我们在投影仪上打开它会发生什么？它肯定不会像您希望的那样工作。

# JavaScript 最佳实践

这个话题没有开始和结束。关于 JavaScript 应该如何完成任务，有很多不同的观点，结果是大多数都是正确的（取决于您的背景、经验和用例）。让我们来看看一些关于 JavaScript（ES5）最常讨论的最佳实践。

# 避免污染全局范围

不要向全局范围添加属性或方法。这将使您的窗口对象膨胀，并使您的页面变得缓慢和不稳定。相反，总是在方法内创建一个变量，在方法被销毁时会被处理。

# 使用'use strict'

这是一个一行的改变，当涉及捕捉代码异味和任何代码不规则性时，可以走很长的路，比如删除一个变量。`use strict`子句在运行时执行非法操作时会抛出错误，因此它并不一定防止我们的应用程序崩溃，但我们可以在部署之前捕捉并修复问题。

# 严格检查（== vs ===）

当涉及到类型转换时，JavaScript 可能是一门相当棘手的语言。没有数据类型使得这一过程变得更加复杂。使用==会强制进行隐式类型转换，而===则不会。因此，建议始终使用===，除非你想让 12== 12 成立。

要了解它为什么会这样工作的更多细节，请参考抽象相等比较算法，网址为[`www.ecma-international.org/ecma-262/5.1/#sec-11.9.3`](https://www.ecma-international.org/ecma-262/5.1/#sec-11.9.3)。

# 使用三元运算符和布尔||或&&

建议始终保持代码可读，但在必要时，使用三元运算符使代码简洁易读：

```js
if(cond1) {
    var1 = val1;
} else {
    var1 = val2
}

if(cond2) {
    var2 = val3;
} else {
    var2 = val4
}
```

例如，上述代码可以简化如下：

```js
var1 = cond1 ? val1 : val2;
var2 = cond2 ? val3 : val4;
```

设置默认值也可以轻松实现如下：

```js
var1 = ifThisVarIsFalsy || setThisValue;
var2 = ifThisVarIsTruthy && setThisValue;
```

# 代码的模块化

当我们创建一个脚本时，很明显我们希望它能做多种事情，例如，如果我们有一个登录页面，登录页面的脚本应该处理登录（显然），重置密码和注册。所有这些操作都需要电子邮件验证。将验证作为每个操作的一部分放入自己的方法中被称为模块化。它帮助我们保持方法小，可读，并且使单元测试变得更容易。

# 避免金字塔式的厄运

金字塔式的厄运是一个经典场景，我们有大量的嵌套或分支。这使得代码过于复杂，单元测试变得非常复杂：

```js
promise1()
    .then((resp) => {
        promise2(resp)
            .then((resp2) => {
                promise3(resp2)
                    .then((resp3) => {
                        if(resp3.something) {
                            // do something
                        } else {
                            // do something else
                        }
                    });
            });
    });
```

而不是，做以下事情：

```js
promise1()
    .then((resp) => {
        return promise2(resp);
    })
   .then((resp2) => {
        return promise3(resp2);
    })                
    .then((resp3) => {
        if(resp3.something) {
            // do something
        } else {
            // do something else
        }
    })

```

# 尽量减少 DOM 访问

DOM 访问是一个昂贵的操作，我们需要尽量减少它，以避免页面崩溃。尝试在访问 DOM 元素后将它们缓存到一些本地变量中，或者利用虚拟 DOM，它更有效，因为它批处理所有 DOM 更改并一起分派它们。

# 验证所有数据

注册新用户？确保所有输入的字段在 UI 和后端都经过验证。在两个地方都这样做会使它变得两倍好，UI 上的验证帮助用户更快地获得错误消息，而不是服务器端验证。

# 不要重复造轮子

当涉及到开源软件和项目时，JavaScript 社区非常慷慨。利用它们；不要重写已经在其他地方可用的东西。重写一些经过社区测试的免费可用软件不值得时间和精力。如果一个软件只满足你需求的 90%，考虑为开源项目贡献剩下的 10%功能。

# HTML 优化

作为网页开发者，我们对创建模板非常熟悉。在这一部分，我们将探讨如何尽可能地提高这个过程的效率。

# DOM 结构

显而易见的是，DOM 结构在渲染 UI 时会产生很大的差异。要使 HTML 模板成为 DOM，需要经历一系列步骤：

1.  **模板解析**：解析器读取 HTML 文件

1.  **标记化**：解析器识别标记，比如`html`和`body`

1.  **词法分析**：解析器将标记转换为标签，比如`<html>`和`<body>`

1.  **DOM 构建**：这是最后一步，浏览器将标记转换为树，同时应用适用的样式和规则给元素

考虑到这一点，重要的是我们不要不必要地嵌套我们的元素。尽量对元素应用样式，而不是将它们嵌套在其他元素中。话虽如此，人们可能会想，这到底有多重要？浏览器在这方面做得相当不错，所以如果我的 DOM 中有一个额外的元素，真的会有多大关系吗？事实上，不会，如果你的 DOM 中有一个额外的元素并不会有关系。然而，想想所有不同的浏览器。还有，你添加这个额外元素的地方有多少；考虑这样一个做法会设定什么样的先例。随着时间的推移，你的开销会开始变得重要起来。

# 预取和预加载资源

`<link>`标签的一些较少为人知的属性是`rel=prefetch`和`rel=preload`选项。它们允许浏览器预加载一些在随后或者有时甚至是当前页面中需要的内容。

# <link rel=prefetch >

让我们讨论一个非常简单的例子来理解预取：加载图像。加载图像是网页执行的最常见操作之一。我们决定加载哪个图像，可以使用 HTML 模板中的`img`标签或 CSS 中的`background-image`属性。

无论如何，直到元素被解析，图像都不会被加载。另外，假设你的图像非常大，需要很长时间才能下载，那么你将不得不依赖于一堆备用方案，比如提供图像尺寸，以便页面不会闪烁，或者在下载失败时使用`alt`属性。

一种可能的解决方案是预取将来需要的资源。这样，你可以避免在用户登陆到该页面之前下载资源。一个简单的例子如下：

```js
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- a very large image -->
  <link rel="prefetch" href="http://gfsnt.no/oen/foto/Haegefjell_Jan_2013_Large.jpg">
</head>

<body>
    <script>
        window.onload = function() {
            setTimeout(function() {
                var x = document.createElement("IMG");
                x.setAttribute("src",
             "http://gfsnt.no/oen/foto/Haegefjell_Jan_2013_Large.jpg");
                document.body.appendChild(x);
            }, 5000);
        }
    </script>
</body>
</html>
```

我们有意延迟了`img`标签的加载，直到预取完成。理想情况下，你会预取下一页所需的资源，但这样也能达到同样的效果。

一旦我们运行这个页面，我们可以看到对图像的请求如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/321a0a8d-d618-4f88-b00b-2a4180924181.png)

这听起来太好了，对吧？是的，尽管这个功能很有用，但在处理跨多个浏览器的预取时会遇到问题。Firefox 只在空闲时预取；一些浏览器可以在用户触发其他操作后暂停下载，然后在浏览器再次空闲时重新下载剩余的图像，但这取决于服务器如何提供可缓存内容（即服务器需要支持提供多部分文件）。然后，有些浏览器可以且会放弃预取，因为网络太慢。

# <link rel=preload >

预加载与预取非常相似，不同之处在于一旦资源下载被触发，浏览器就没有放弃下载的选择。

语法也非常相似，只是我们定义了我们试图预加载的资源的类型：

```js
<link rel="preload" href="http://gfsnt.no/oen/foto/Haegefjell_Jan_2013_Large.jpg" as="image">
```

预取和预加载在下载字体和字体系列时也是一个非常常见的选择，因为加载字体的请求直到 CSSOM 和 DOM 都准备好才会被触发。

# HTML 的布局和分层

为 UI 渲染元素设计 HTML 模板是作为 Web 开发人员最简单的任务之一。在本节中，我们将讨论 Chrome 如何处理模板并将其渲染到 UI 上。HTML 模板有两个关键部分，布局和层，我们将看一些例子，以及它们如何影响页面性能。

# HTML 布局

让我们从一个非常简单的网页开始，看看 Chrome 如何处理渲染这个页面：

```js
<!DOCTYPE html>
<html>
    <head></head>

    <body>
        <div>test</div>
    </body>
</html>
```

一旦我们加载页面，我们将使用 Chrome**开发者工具**（**DevTools**）生成这个模板加载的性能快照。要这样做，导航到 Chrome 浏览器上的 CDT（设置->更多工具->开发者工具）。

一旦我们到达那里，让我们通过点击打开面板左上角的记录按钮来记录一个新的快照。一旦你的页面加载完成，停止录制，让快照在面板中加载。结果如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/54f8d076-62e1-4693-a568-296d544c0175.png)

难以理解，对吧？好吧，让我们把它分解成我们可以理解的小块。我们的主要关注点将是`main`部分（在截图中展开）。让我们放大一下，看看从左到右的事件是什么。

首先，我们将看到 beforeunload 事件：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/51ace852-0b26-492b-aacc-79bda81c73ee.png)

接下来，我们将看到更新图层树（我们稍后会讨论）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/266d1ed6-7cc7-4da3-b92c-0deb63079235.png)

现在我们注意到一个 Minor GC，这是一个特定于浏览器的事件（我们将在后面的部分讨论这个）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/581f7229-dd5a-432e-af44-fcffb4d37f11.png)

然后，我们将注意`DOMContentLoaded`事件，然后是`Recalculate Style`事件，这是当我们的页面准备好进行交互时发生的事件：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/a171491a-16f2-49a4-bf80-949a8d0e8009.png)

很酷，对吧？这与我们之前听说的浏览器完全一致。它们加载页面，然后在一切准备就绪时触发`DOMContentLoaded`。然而，请注意，还有另一个被触发的事件叫做 Minor GC。我们可以忽略这个，因为它是由浏览器内部处理的，与我们的代码结构几乎没有关系。

一旦 DOM 加载完成，我们注意到另一个被触发的事件叫做`Recalculate Style`，这正是它听起来的样子。DOM 已经准备好了，浏览器会检查并应用需要应用到这个元素的所有样式。然而，你可能会想，我们没有向我们的模板添加任何样式，对吧？那么，我们在谈论什么样式呢？默认情况下，所有浏览器都会向它们渲染的所有元素应用样式，这些被称为用户代理样式表。浏览器仍然需要将用户代理样式表样式添加到 CSSOM 中。

除了它是浏览器将安排元素的几何结构之外，我们还没有真正讨论`Layout`是什么，包括但不限于它们在页面上的大小、形状和位置。`Layout`也是一个事件，将被 CDT 记录下来，以显示浏览器在尝试重新排列布局时花费了多长时间。我们尽量将布局事件保持在最小范围内非常重要。为什么？因为`Layout`不是一个孤立的事件。它是由一系列其他事件（例如更新图层树和绘制 UI）链接在一起的，这些事件需要完成 UI 上元素的排列。

另一个重要的事情要考虑的是，`Layout`事件会为页面上受影响的所有元素触发，也就是说，即使一个深度嵌套的元素被改变，你的整个元素（或者根据改变而改变的周围元素）都会被重新布局。让我们看一个例子：

```js
<!DOCTYPE html>
<html>
    <head>

        <style>
            .parent {
                border: 1px solid black;
                padding: 10px;
            }

            .child {
                height: 20px;
                border: 1px solid red;
                padding: 5px;
            }
        </style>

    </head>

    <body>
        <div class="parent">
            <div class="child">
                child 1
            </div>
            <div class="child">
                child 2
            </div>
            <div class="child">
                child 3
            </div>
            <div class="child">
                child 4
            </div>
        </div>

        <button onclick="updateHeight();">update height</button>

        <script>
            function updateHeight() {
                var allEl = document.getElementsByTagName('div');
                var allElemLength = allEl.length;

                for(var i = 0; i < allElemLength; i++) {
                    allEl[i].style.height = '100px';
                }

            }
        </script>
    </body>
</html>
```

这很简单；我们有一个包含四个子元素的非常小的父元素的页面。我们有一个按钮，它将所有元素的高度设置为`100px`。现在让我们运行这个页面，并跟踪当我们点击按钮`update height`来改变元素的高度时的性能，我们在 UI 上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/f79f82f7-c9ed-4cd4-a22f-d6a6312d30a3.png)

我们可以从前面的截图中看到，一旦点击事件开始，它触发了我们的函数，然后触发了一系列事件，包括`Layout`，用时 0.23 毫秒。然而，你可能会想，为什么在`Function`和`Layout`之间有一个`Recalculate Style`事件？还记得我们的老朋友用户代理样式表吗？它在按钮激活时设置了一些样式，这触发了`Recalculate Style`事件。

如果您想要删除元素的所有样式（例如在前面描述的按钮中），您可以通过将`all:unset`属性应用于您选择的元素来这样做。这将完全取消元素的样式。但是，它将减少`Recalculate Style`事件的时间，使其成为应用用户代理样式的一小部分。

现在让我们将 JavaScript 函数更改为仅更改页面上的第一个子元素的样式，而不是所有元素，并看看这如何影响我们的情况下`Layout`事件的执行：

```js
function updateHeight() {
 var allEl = document.getElementsByTagName('div');    
 allEl[1].style.height = '100px';  }
```

现在，当我们运行页面并分析点击方法的执行时，我们将在分析器中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/572fd447-4897-46b1-9042-c17a91bf5378.png)

正如您在前面的屏幕截图中看到的，整个页面的布局仍然需要 0.21 毫秒，这与我们先前的值并没有太大不同。在我们先前的示例中，我们有五个更多的元素。但是，在生产应用程序中，这可能会扩展到数千个元素，并且为了平稳过渡，我们希望保持我们的`Layout`事件在 16 毫秒以下（60fps）。

很可能，您可能永远不会遇到这个问题，但如果您遇到了，处理它的最简单方法是首先检查您的浏览器是否支持最新的布局模型。在大多数浏览器中，它将是 flexbox 或 grid，因此最好选择它而不是浮动、百分比或定位。

# HTML 图层

正如我们在前面的示例中所看到的，一旦元素重新布局，我们就会`Paint`元素，也就是说，用颜色填充像素，这应该是元素在给定位置的一部分（由`Layout`确定）。

一旦`Paint`事件完成，浏览器就会执行`Composition`，基本上是我们的浏览器将页面的所有部分放在一起。部分越少，页面加载速度就越快。此外，如果`Composition`的某个部分花费太长时间，那么整个页面加载就会延迟。

我们如何处理这些花费太长时间的操作？我们可以通过将它们提升到它们自己的图层来处理。有一些 CSS 操作，我们可以对元素执行，这将使它们提升到它们自己的图层。这对我们意味着什么？这些提升的元素现在将被延迟并在 GPU 上作为纹理执行。我们不再需要担心我们的浏触发这些提升元素的`Layout`或`Paint`事件，我们只关心元素的`Composition`。

从前面的示例中，到目前为止，我们已经确定了任何更改流程的前四个步骤如下：

1.  JavaScript 文件被执行

1.  样式重新计算

1.  `Layout`事件

1.  `Paint`事件

现在，我们可以将以下步骤添加到列表中，以完全在 UI 上呈现元素：

5. `Composition`

6. 多线程光栅化

*步骤 6*仅仅是将我们的像素渲染到 UI 上，可以批处理并在并行线程上运行。让我们创建一个简单的 HTML 并看看它如何渲染到 UI 上的单个图层：

```js
<!DOCTYPE html>
<html>
<head>

</head>

<body>
    <div>
        Default Layer
    </div>
</body>
</html>
```

我们可以通过导航到“设置”选项，然后选择“更多工具”和“图层”来从 DevTool 中访问图层。在加载先前显示的页面时，我们将在图层中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/22386b4f-25e5-4522-b94b-f2382afa915b.png)

当我们对前面的页面进行分析时，我们可以看到，如预期的那样，页面在`Main`线程上加载和呈现 UI：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/4d72a23b-6be1-4df8-8512-2d1153d50d58.png)

现在让我们将此示例更改为加载到自己的图层上，以便我们可以完全跳过`Layout`和`Paint`部分。要将元素加载到自己的图层上，我们只需要给它一个 CSS 变换或将`will-change`属性设置为 transform:

```js
.class-name {
    will-change: transform:
    // OR
    transform: translateZ(0); <- does nothing except loading to a new Layer
}
```

以下是一个更新后的示例模板，它使用 CSS3`transform`属性：

```js
<!DOCTYPE html>
<html>
<head>
    <style>
        div {
            width: 100px;
            height: 100px;
            margin: 200px;
            border: 1px solid black;
            animation: spin 1s infinite;
            transition: all 0.35s ease;
        }

        @keyframes spin {
            from {
                transform: rotate(0deg);
            }

            to {
                transform: rotate(360deg);
            }
        }
    </style>
</head>

<body>
    <div></div>
</body>
</html>
```

在前面的代码中，我们添加了一个非常小的动画，它将无限旋转元素。当我们重新加载页面时，我们可以看到它已被添加到自己的图层中：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/c948a949-970a-4661-ba96-c92d1f7e34ca.png)

不仅如此，当我们记录修改模板的性能时，我们会看到一些非常有趣的东西：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/67735520-b4cb-47f3-9140-4f49d5a87138.png)

正如我们在前面的截图中看到的，浏览器完全将“层”推迟到 GPU 作为新的纹理，从那时起，GPU 处理元素的渲染/更新，而不是浏览器。

好吧，这是否意味着我们将每个元素加载到自己的“层”上，然后让 GPU 接管？当然不是，因为每个“层”在内部都需要内存，并且将成千上万的元素加载到每个“层”上将是适得其反的。例如，我们有意将元素提升到自己的“层”的唯一时间是当元素在“合成”期间花费太长时间，并且正在阻碍操作，例如滚动或滑动时。另一个用例可能是当您有一个单一元素执行多个更改时，例如动画高度、宽度和背景颜色。这将不断调用渲染过程的所有步骤（从“布局”到光栅化），如果我们知道它仅限于这些少量更改，那么我们实际上不需要做所有这些。我们可以简单地将此元素提升到自己的层并完成。

# CSS 优化

如果您有使用任何预处理器框架（如 SCSS/LESS）的开发经验，那么 CSS 优化非常容易并且显而易见。当我们讨论 CSS 优化时，我们实际上在谈论两个不同但又相关的事情：

+   加载样式表

+   渲染和应用样式

# 编码实践

有许多编码实践可以适应和学习，以使我们的应用程序表现更好。其中大多数可能看起来微不足道，但当扩展到大型应用程序时确实很重要。我们将用示例讨论其中一些技术。

# 对常见的 ENUM 使用较小的值

由于我们正在讨论减少页面加载时间，因此一种快速的方法是通过删除 CSS 文件本身中的冗余来实现：

+   使用`#FFFFFF`？改用`#FFF`，这是相同的 RGB 值，用简短表示。

+   如果值为`0`，则不要在属性值后添加`px`。

+   如果尚未使用，请使用缩小。这会将所有正在使用的 CSS 文件连接起来，并删除所有空格和换行符。

+   在通过网络传输时使用 GZip 压缩已经被缩小的文件。这很容易，浏览器非常擅长高效地解压文件。

+   注意手头的特定于浏览器的优化。例如，在 Chrome 的情况下，我们不必以`rgba(x,y,z,a)`格式应用样式。我们可以在开发过程中应用它为`rgba`，并使用 DevTool 提取相应的 HEX 值。简单地检查相关元素，同时按下*Shift*点击小矩形：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/e80a8814-de08-45cf-a14c-b60e7b7ee381.png)

# 使用简写属性

使用简写属性是加快页面加载速度的一种方法。尽管听起来很明显，但有时候当我们在舒适的笔记本电脑上工作时，我们会认为浏览器和网络是理所当然的，而忘记考虑那些使用 3G 设备的用户。因此，下次您想要为元素设置背景或边框样式时，请确保它们都被折叠并使用简写方式编写。

有时，您可能会遇到这样的情况，您只想覆盖某个元素样式的一个属性。例如，如果您想在元素的三个边上应用边框，请使用以下方法：

```js
.okay {
    border-left: 1px solid black;
    border-right: 1px solid black;
    border-bottom: 1px solid black;
} // 114 characters including spaces

.better {
    border: 1px solid black;
    border-top: 0;
} // 59 characters including spaces
```

# 避免复杂的 CSS 选择器

每当您创建 CSS 样式时，都必须了解将这些样式应用于任何元素对浏览器都有成本。我们可以像分析 JavaScript 一样分析我们的 CSS 选择器，并得出我们应用的每种样式的最佳和最坏情况运行时性能。

例如，考虑我们有以下样式：

```js
.my-class > div > ul.other-class .item:nth-child(3) {
```

这种复杂性要比简单地创建一个类并直接分配给元素本身要高得多：

```js
.my-class-child {
```

我们的浏览器不再需要检查每个元素是否完全符合先前定义的样式层次结构。基于这个概念发展出的一种技术称为**块-元素-修饰符**（**BEM**），这是非常容易理解的。给您的元素一个单一的类名，并尽量不要嵌套它们：

因此，假设您的模板如下所示：

```js
<div class="nav">
 <a href="#" class="nav__trigger">hamburger_icon</a>   <ul class="nav__items"> <li class="nav__item"> <a href="#" class="nav__link">About</a> </li>   <li class="nav__item"> <a href="#" class="nav__link">Blog</a> </li>   <li class="nav__item"> <a href="#" class="nav__link">Contact</a> </li> </ul> </div>
```

您可以使用 BEM 应用样式，如下所示：

```js
.nav {
    /* styles */ }

.nav__items {
    /* styles */ }

.nav__item {
    /* styles */ }

.nav__link {
    /* styles */ }

.nav__link--active {
    /* styles */ }
```

如果您需要为元素添加自定义样式，可以创建一个新类并直接应用，或者可以将嵌套与当前级别结合起来：

```js
.nav__item--last-child--active {
    /* styles */ }
```

# 理解浏览器

与 HTML 渲染类似，CSS 解析和渲染也是复杂的过程，浏览器非常轻松地隐藏了这些过程。了解我们可以避免什么总是有好处的。让我们以与 HTML 相同的示例为例，讨论 Chrome 如何处理这些问题。

# 避免重绘和回流

让我们首先简要讨论一下重绘和回流是什么：

**重绘**：浏览器在元素的非几何属性发生变化时执行的操作，例如背景颜色、文本颜色等。

**回流**：浏览器执行的操作，因为元素（或其父元素）的几何变化，直接或通过计算属性。这个过程与之前讨论的`Layout`相同。

虽然我们无法完全防止重绘和回流事件，但我们肯定可以在最小化触发这些操作的更改中发挥作用。几乎所有 DOM `read`操作（例如`offsetWidth`和`getClientRects`）都会触发`Layout`事件，因为这些读操作的值是按需进行的，浏览器在明确请求之前不关心它们的值。此外，每当我们修改 DOM 时，`Layout`都会失效，如果我们需要下次读取 DOM 元素属性，它将不得不重新计算。

# 关键渲染路径（CRP）

到目前为止，我们已经看到了如何优化页面加载（减少负载、大小等），然后我们谈到了渲染后需要考虑的事情。关键渲染路径是优化页面加载的技术，即在折叠线之上（即在任何滚动之前显示的页面顶部部分）的初始加载。这也被称为**交互时间**（**TTI**）或**首字节时间**（**TTFB**），我们希望减少以保持页面加载速度。

从技术上讲，CRP 包括以下步骤：

1.  接收并开始解析 HTML。

1.  下载并构建 CSSOM。

1.  下载并执行 JS。

1.  完成构建 DOM。

1.  创建渲染树。

因此，如果我们希望我们的 TTI 低，很明显，我们需要尽快构建我们的 DOM 和 CSSOM，而不需要任何阻塞渲染的 CSS 或阻塞解析器的 JS 文件。我们的 TTI 低的一个指标是我们的`DOMContentLoaded`事件快速触发，因为 DCL 仅在 DOM 和 CSSOM 准备就绪时触发。让我们看下面的示例模板：

```js
<html>
<head>
    <title>CRP Blank</title>
</head>
<body>
    <div>Blank</div>
</body>
</html>
```

我们可以看到它非常简洁，甚至没有加载任何外部样式或脚本。这对于网页来说非常不寻常，但它作为一个很好的例子。当我们运行这个页面并打开网络选项卡时，我们可以看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/1bb2c85f-d936-4678-b647-c3e2c7ffe398.png)

然而，我们提到的 HTML 是非常不寻常的。很可能，我们将加载多个外部 CSS 和 JS 文件到我们的页面中。在这种情况下，我们的 DCL 事件会被延迟。让我们在`blank.html`文件中添加空白的 CSS 和 JS 文件以加载：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/a2b4363a-4909-4a4f-b2fb-b0a217c6fc6a.png)

在这里，我们可以看到，即使没有太多要加载，DCL 事件也被推迟，直到浏览器下载并运行 JS 文件，因为 JS 文件的获取和执行是渲染阻塞操作。我们的目标现在更加明确：我们需要将 DCL 减少到最低限度，并且从目前我们已经看到的情况来看，我们需要尽快加载 HTML，而其他所有内容可以在初始页面被渲染后（或者至少正在被渲染时）加载。之前我们已经看到，我们可以使用 `async` 关键字和脚本标签一起使 JavaScript 异步加载和执行。现在让我们使用相同的方法来使我们的页面加载更快：

```js
<html>
<head>
    <title>CRP Blank</title>
    <link rel="stylesheet" href="blank.css">
</head>
<body>
    <div>Blank</div>

    <script async src="blank.js"></script>
</body>
</html>
```

现在，当我们打开网络选项卡运行这个页面时，我们会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/45273501-86bf-46b9-9d2e-0fbfbb2431a1.png)

我们可以看到 DCL（在 *瀑布* 选项卡下表示为蓝色垂直线）发生在 CSS 和 JS 文件被下载和执行之前。使用 `async` 属性的另一个优势是，`async` 属性表示 JavaScript 不依赖于 CSSOM，因此不需要被 CSSOM 构建阻塞。

# JavaScript 优化

有大量的在线资源可以讨论可以应用于 JavaScript 的各种优化。在本节中，我们将看一些这些微优化，并确定我们如何采取小步骤使我们的 JavaScript 更高效。

# 真值/假值比较

我们都曾经在某个时候编写过 if 条件或者依赖于 JavaScript 变量的真值或假值来分配默认值。尽管大多数时候这很有帮助，但我们需要考虑这样一个操作对我们的应用程序会造成什么影响。然而，在我们深入细节之前，让我们讨论一下在 JavaScript 中如何评估任何条件，特别是在这种情况下的 if 条件。作为开发者，我们倾向于做以下事情：

```js
if(objOrNumber) {
    // do something
}
```

这对大多数情况都适用，除非数字是 0，这种情况下会被评估为 false。这是一个非常常见的边缘情况，我们大多数人都会注意到。然而，JavaScript 引擎为了评估这个条件需要做些什么呢？它如何知道 objOrNumber 评估为 true 还是 false？让我们回到我们的 ECMA262 规范并提取 IF 条件规范 ([`www.ecma-international.org/ecma-262/5.1/#sec-12.5`](https://www.ecma-international.org/ecma-262/5.1/#sec-12.5))。以下是同样的摘录：

语义

The production IfStatement : If (Expression) Statement else Statement

Statement 的评估如下：

1.  让 exprRef 成为评估 Expression 的结果。

1.  如果 ToBoolean(GetValue(exprRef)) 是 true，那么

+   返回评估第一个 Statement 的结果。

1.  否则，

+   返回评估第二个 Statement 的结果。

现在，我们注意到我们传递的任何表达式都经历以下三个步骤：

1.  从 `Expression` 获取 `exprRef`。

1.  `GetValue` 在 `exprRef` 上调用。

1.  `ToBoolean` 被作为 *步骤 2* 的结果调用。

*步骤 1* 在这个阶段并不关心我们太多；可以这样想——一个表达式可以是像 `a == b` 这样的东西，也可以是像 `shouldIEvaluateTheIFCondition()` 方法调用这样的东西，也就是说，它是用来评估你的条件的东西。

*步骤 2* 提取了 `exprRef` 的值，也就是 10、true、undefined。在这一步中，我们根据 `exprRef` 的类型区分了值是如何提取的。你可以参考 [`www.ecma-international.org/ecma-262/5.1/#sec-8.7.1`](https://www.ecma-international.org/ecma-262/5.1/#sec-8.7.1) 中 `GetValue` 的详细信息。

*步骤 3* 然后根据以下表格（取自 [`www.ecma-international.org/ecma-262/5.1/#sec-9.2`](https://www.ecma-international.org/ecma-262/5.1/#sec-9.2)）将从 *步骤 2* 中提取的值转换为布尔值：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/3c9cc47e-b91e-414d-80ab-ef45d24f106b.png)

在每一步，您可以看到，如果我们能够提供直接的布尔值而不是真值或假值，那么总是有益的。

# 循环优化

我们可以深入研究 for 循环，类似于我们之前对 if 条件所做的（[`www.ecma-international.org/ecma-262/5.1/#sec-12.6.3`](https://www.ecma-international.org/ecma-262/5.1/#sec-12.6.3)），但是在循环方面可以应用更简单和更明显的优化。简单的更改可以极大地影响代码的质量和性能；例如：

```js
for(var i = 0; i < arr.length; i++) {
    // logic
}
```

前面的代码可以更改如下：

```js
var len = arr.length;

for(var i = 0; i < len; i++) {
    // logic
}
```

更好的是以相反的方式运行循环，这比我们之前看到的更快：

```js
var len = arr.length;

for(var i = len; i >= 0; i--) {
    // logic
}
```

# 条件函数调用

我们应用程序中的一些功能是有条件的。例如，日志记录或分析属于这一类。一些应用程序可能会在某段时间内关闭日志记录，然后重新打开。实现这一点最明显的方法是将日志记录方法包装在 if 条件中。但是，由于该方法可能被触发多次，我们可以以另一种方式进行优化：

```js
function someUserAction() {

    // logic

    if (analyticsEnabled) {
        trackUserAnalytics();
    }

}

// in some other class

function trackUserAnalytics() {

    // save analytics

}
```

不是前面的方法，我们可以尝试做一些稍微不同的事情，这样 V8 引擎可以优化代码的执行方式：

```js
function someUserAction() {

    // logic

   trackUserAnalytics();
}

// in some other class

function toggleUserAnalytics() {

    if(enabled) {
        trackUserAnalytics =  userAnalyticsMethod;
    } else {
        trackUserAnalytics = noOp;
    }
}

function userAnalyticsMethod() {

    // save analytics

}

// empty function
function noOp  {}
```

现在，前面的实现是一把双刃剑。原因很简单。JavaScript 引擎采用一种称为**内联缓存**（**IC**）的技术，这意味着 JS 引擎对某个方法的任何先前查找都将被缓存并在下次触发时重用；例如，如果我们有一个具有嵌套方法的对象 a.b.c，方法 a.b.c 只会被查找一次并存储在缓存中（IC）；如果下次调用 a.b.c，它将从 IC 中获取，并且 JS 引擎不会再次解析整个链。如果 a.b.c 链有任何更改，那么 IC 将被使无效，并且下次将执行新的动态查找，而不是从 IC 中检索。

因此，从我们之前的例子中，当我们将`noOp`分配给`trackUserAnalytics()`方法时，该方法路径被跟踪并保存在 IC 中，但它在内部删除了这个函数调用，因为它是对一个空方法的调用。但是，当它应用于具有一些逻辑的实际函数时，IC 直接指向这个新方法。因此，如果我们多次调用我们的`toggleUserAnalytics()`方法，它将不断使我们的 IC 失效，并且我们的动态方法查找必须每次发生，直到应用程序状态稳定下来（也就是说，不再调用`toggleUserAnalytics()`）。

# 图像和字体优化

在图像和字体优化方面，我们可以进行各种类型和规模的优化。但是，我们需要牢记我们的目标受众，并根据手头的问题调整我们的方法。

对于图像和字体，首要重要的是我们不要过度提供，也就是说，我们只请求和发送应用程序运行设备的尺寸所需的数据。

最简单的方法是为设备大小添加一个 cookie，并将其与每个请求一起发送到服务器。一旦服务器收到图像的请求，它可以根据发送到 cookie 的图像尺寸检索图像。大多数时候，这些图像是用户头像或评论某篇帖子的人员列表之类的东西。我们可以同意缩略图图像不需要与个人资料页面的大小相同，我们可以在传输基于图像的较小图像时节省一些带宽。

由于现在的屏幕具有非常高的**每英寸点数**（**DPI**），我们为屏幕提供的媒体需要值得。否则，应用程序看起来很糟糕，图像看起来都是像素化的。这可以通过使用矢量图像或`SVGs`来避免，这些图像可以通过网络进行 GZip 压缩，从而减小负载大小。

另一个不那么明显的优化是更改图像压缩类型。您是否曾经加载过一个页面，其中图像从顶部到底部以小的增量矩形加载？默认情况下，图像使用基线技术进行压缩，这是一种自上而下压缩图像的默认方法。我们可以使用诸如`imagemin`之类的库将其更改为渐进式压缩。这将首先以模糊的方式加载整个图像，然后是半模糊，依此类推，直到整个图像未经压缩地显示在屏幕上。解压渐进式 JPEG 可能需要比基线更长的时间，因此在进行此类优化之前进行测量非常重要。

基于这一概念的另一个扩展是一种仅适用于 Chrome 的图像格式，称为`WebP`。这是一种非常有效的图像服务方式，在生产中为许多公司节省了近 30%的带宽。使用`WebP`几乎和之前讨论的渐进式压缩一样简单。我们可以使用`imagemin-webp`节点模块，它可以将 JPEG 图像转换为`webp`图像，从而大大减小图像大小。

Web 字体与图像有些不同。图像会按需下载并呈现到 UI 上，也就是说，当浏览器从 HTML 或 CSS 文件中遇到图像时。然而，字体则有些不同。字体文件只有在渲染树完全构建时才会被请求。这意味着在发出字体请求时，CSSOM 和 DOM 必须准备就绪。此外，如果字体文件是从服务器而不是本地提供的，那么我们可能会看到未应用字体的文本（或根本没有文本），然后我们看到应用了字体，这可能会导致文本的闪烁效果。

有多种简单的技术可以避免这个问题：

+   在本地下载、提供和预加载字体文件：

```js
<link rel="preload" href="fonts/my-font.woff2" as="font">
```

+   在字体中指定 unicode 范围，以便浏览器可以根据实际期望的字符集和字形进行适应和改进：

```js
@font-face(
    ...
    unicode-range: U+000-5FF; // latin
    ...
)
```

+   到目前为止，我们已经看到我们可以将未经样式化的文本加载到 UI 上，并且按照我们期望的方式进行样式化；这可以通过使用字体加载 API 来改变，该 API 允许我们使用 JavaScript 加载和呈现字体：

```js
var font = new FontFace("myFont", "url(/my-fonts/my-font.woff2)", {
    unicodeRange: 'U+000-5FF'  });

// initiate a fetch without Render Tree font.load().then(function() {
   // apply the font 
  document.fonts.add(font);

   document.body.style.fontFamily = "myFont";  });
```

# JavaScript 中的垃圾回收

让我们快速看一下**垃圾回收**（**GC**）是什么，以及我们如何在 JavaScript 中处理它。许多低级语言为开发人员提供了在其代码中分配和释放内存的显式能力。然而，与这些语言不同，JavaScript 自动处理内存管理，这既是好事也是坏事。好处是我们不再需要担心需要分配多少内存，何时需要这样做，以及如何释放分配的内存。整个过程的坏处是，对于一个不了解的开发人员来说，这可能是一场灾难，他们可能最终得到一个可能会挂起和崩溃的应用程序。

幸运的是，理解 GC 的过程非常容易，并且可以很容易地融入到我们的编码风格中，以确保在内存管理方面编写最佳代码。内存管理有三个非常明显的步骤：

1.  将内存分配给变量：

```js
var a = 10; // we assign a number to a memory location referenced by variable a
```

1.  使用变量从内存中读取或写入：

```js
a += 3; // we read the memory location referenced by a and write a new value to it
```

1.  当不再需要时，释放内存。

现在，这是不明显的部分。浏览器如何知道我们何时完成变量`a`并且它已准备好进行垃圾回收？在我们继续讨论之前，让我们将其包装在一个函数中：

```js
function test() {
    var a = 10;
    a += 3;
    return a;
}
```

我们有一个非常简单的函数，它只是将我们的变量`a`相加并返回结果，然后执行结束。然而，实际上还有一步，这将在这个方法执行后发生，称为**标记和清除**（不是立即发生，有时也会在主线程上完成一批操作后发生）。当浏览器执行标记和清除时，它取决于应用程序消耗的总内存和内存消耗的速度。

# 标记和清除算法

由于没有准确的方法来确定特定内存位置的数据将来是否会被使用，我们将需要依赖于可以帮助我们做出这个决定的替代方法。在 JavaScript 中，我们使用**引用**的概念来确定变量是否仍在使用，如果不是，它可以被垃圾回收。

标记和清除的概念非常简单：从所有已知的活动内存位置到达哪些内存位置？如果有些地方无法到达，就收集它，也就是释放内存。就是这样，但是已知的活动内存位置是什么？它仍然需要一个起点，对吧？在大多数浏览器中，GC 算法会保留一个`roots`列表，从这些`roots`开始标记和清除过程。所有`roots`及其子代都被标记为活动，可以从这些`roots`到达的任何变量也被标记为活动。任何无法到达的东西都可以标记为不可到达，因此可以被收集。在大多数情况下，`roots`包括 window 对象。

所以，我们将回到之前的例子：

```js
function test() {
    var a = 10;
    a += 3;
    return a;
}
```

我们的变量 a 是局部的`test()`方法。一旦方法执行，就无法再访问该变量，也就是说，没有人持有该变量的引用，这时它可以被标记为垃圾回收，这样下次 GC 运行时，`var a`将被清除，分配给它的内存可以被释放。

# 垃圾回收和 V8

在 V8 中，垃圾回收的过程非常复杂（应该是这样）。因此，让我们简要讨论一下 V8 是如何处理的。

在 V8 中，内存（堆）分为两个主要代，即**新生代**和**老生代**。新生代和老生代都分配了一些内存（在*1MB*和*20MB*之间）。大多数程序和它们的变量在创建时都分配在新生代中。每当我们创建一个新变量或执行一个消耗内存的操作时，默认情况下会从新生代分配内存，这对内存分配进行了优化。一旦分配给新生代的总内存几乎被完全消耗，浏览器就会触发一个**Minor GC**，它基本上会删除不再被引用的变量，并标记仍然被引用且暂时不能被删除的变量。一旦一个变量经历了两次或更多次**Minor GC**，那么它就成为了老生代的候选对象，老生代的 GC 周期不像新生代那样频繁。当老生代达到一定大小时，会触发一个 Major GC，所有这些都由应用程序的启发式驱动，这对整个过程非常重要。因此，编写良好的程序会将更少的对象移动到老生代，从而触发更少的 Major GC 事件。

毋庸置疑，这只是对 V8 垃圾回收的一个非常高层次的概述，由于这个过程随着时间的推移不断变化，我们将转变方向，继续下一个主题。

# 避免内存泄漏

现在我们已经大致了解了 JavaScript 中垃圾回收的工作原理，让我们来看一些常见的陷阱，这些陷阱会阻止浏览器标记我们的变量进行垃圾回收。

# 将变量分配给全局范围

现在这应该是显而易见的了；我们讨论了 GC 机制如何确定根（即 window 对象）并将根及其子对象视为活动对象，永远不会标记它们进行垃圾回收。

所以，下次当你忘记在变量声明中添加`var`时，请记住你创建的全局变量将永远存在，永远不会被垃圾回收：

```js
function test() {
    a = 10; // created on window object
    a += 3;
    return a;
}
```

# 删除 DOM 元素和引用

非常重要的是，我们要尽量减少对 DOM 的引用，因此我们喜欢执行的一个众所周知的步骤是在我们的 JavaScript 中缓存 DOM 元素，这样我们就不必一遍又一遍地查询任何 DOM 元素。然而，一旦 DOM 元素被移除，我们需要确保这些方法也从我们的缓存中移除，否则它们永远不会被 GC 回收：

```js
var cache = {row: document.getElementById('row') };

function removeTable() {
 document.body.removeChild(document.getElementById('row'));
}
```

先前显示的代码从 DOM 中删除了`row`，但变量 cache 仍然引用 DOM 元素，因此阻止它被垃圾回收。这里还有一件有趣的事情需要注意，即使我们删除了包含`row`的表，整个表仍将保留在内存中，并且不会被 GC 回收，因为在内部引用表的 cache 中的`row`仍然指向表。

# 闭包边缘情况

闭包很棒；它们帮助我们处理很多棘手的情况，还为我们提供了模拟私有变量概念的方法。好吧，这一切都很好，但有时我们倾向于忽视与闭包相关的潜在缺点。这就是我们所知道和使用的。

```js
function myGoodFunc() {
 var a = new Array(10000000).join('*'); 
    // something big enough to cause a spike in memory usage   function myGoodClosure() {
        return a + ' added from closure';
    }

 myGoodClosure();
}

setInterval(myGoodFunc, 1000);
```

当我们在浏览器中运行这个脚本，然后对其进行分析，我们会看到预期的结果，即该方法消耗了恒定的内存量，然后被 GC 回收，并恢复到脚本消耗的基线内存：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/ff54858d-f532-4323-85de-f1c5c9b62ee8.png)

现在，让我们放大到其中一个峰值，并查看调用树，以确定在峰值时触发了哪些事件：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/6de48c89-3b37-43ef-834c-80fd809b704c.png)

我们可以看到一切都按照我们的预期发生；首先，我们的`setInterval()`被触发，调用`myGoodFunc()`，一旦执行完成，就会有一个 GC，它收集数据，因此会有一个峰值，正如我们从前面的截图中所看到的。

现在，这是处理闭包时预期的流程或正常路径。然而，有时我们的代码并不那么简单，我们最终会在一个闭包中执行多个操作，有时甚至会嵌套闭包：

```js
function myComplexFunc() {
   var a = new Array(1000000).join('*');
   // something big enough to cause a spike in memory usage    function closure1() {
      return a + ' added from closure';
   }

   closure1();

   function closure2() {
      console.log('closure2 called')
   }

   setInterval(closure2, 100);
}

setInterval(myComplexFunc, 1000);
```

我们可以注意到在前面的代码中，我们扩展了我们的方法以包含两个闭包：`closure1`和`closure2`。尽管`closure1`仍然执行与以前相同的操作，但`closure2`将永远运行，因为我们将其运行频率设置为父函数的 1/10。此外，由于两个闭包方法共享父闭包作用域，在这种情况下变量 a，它永远不会被 GC 回收，从而导致巨大的内存泄漏，可以从以下的分析中看到：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/81fb9ed7-2efd-4b8c-ba7e-d6da22d66fc4.png)

仔细观察，我们可以看到 GC 正在被触发，但由于方法被调用的频率，内存正在慢慢泄漏（收集的内存少于创建的内存）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/34a5a920-3ea6-4e32-bab8-ab8fb0c6fc57.png)

好吧，这是一个极端的边缘情况，对吧？这比实际更理论化——为什么会有人有两个嵌套的`setInterval()`方法和闭包。让我们看看另一个例子，其中我们不再嵌套多个`setInterval()`，但它是由相同的逻辑驱动的。

假设我们有一个创建闭包的方法：

```js
var something = null;

function replaceValue () {
   var previousValue = something;

   // `unused` method loads the `previousValue` into closure scope
  function </span>unused() {
      if (previousValue)
         console.log("hi");
   }

   // update something    something = {
      str: new Array(1000000).join('*'),

      // all closures within replaceValue share the same
 // closure scope hence someMethod would have access // to previousValue which is nothing but its parent // object (`something`)     // since `someMethod` has access to its parent // object, even when it is replaced by a new (identical) // object in the next setInterval iteration, the previous // value does not get garbage collected because the someMethod // on previous value still maintains reference to previousValue // and so on.    someMethod: function () {}
   };
}

setInterval(replaceValue, 1000);
```

解决这个问题的一个简单方法是显而易见的，因为我们自己已经说过，对象 `something` 的先前值不会被垃圾回收，因为它引用了上一次迭代的 `previousValue`。因此，解决这个问题的方法是在每次迭代结束时清除 `previousValue` 的值，这样在卸载时 `something` 就没有任何东西可引用，因此可以看到内存分析的变化：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/8c92b433-689b-4d11-b436-c1c08ad66748.png)

前面的图片变化如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/603b37ed-b4ce-4155-9da2-be22cc8452a9.png)

# 总结

在本章中，我们探讨了通过对我们为应用程序编写的 HTML、CSS 和 JavaScript 进行优化来改善代码性能的方法。非常重要的是要理解，这些优化可能对你有益，也可能没有，这取决于你尝试构建的应用程序。本章的主要收获应该是能够打开浏览器的内部，并且不害怕解剖和查看浏览器如何处理我们的代码。此外，要注意 ECMA 规范指南不断变化，但浏览器需要时间来跟上这些变化。最后但同样重要的是，不要过度优化或过早优化。如果遇到问题，首先进行测量，然后再决定瓶颈在哪里，然后再制定优化计划。

# 接下来是什么？

随着这一点，我们结束了这本书。我们希望你有一个很棒的学习经验，并且能够从这些技术中受益。JavaScript，就像它现在的样子，一直在不断发展。事情正在以快速的速度发生变化，跟上这些变化变得很困难。以下是一些建议，你可以尝试并修改：

1.  确定你感兴趣的领域。到现在为止，你已经知道 JavaScript 存在（并且在浏览器之外的很多东西中都很棒）。你更喜欢用户界面吗？你喜欢 API 和可扩展的微服务吗？你喜欢构建传感器来计算你每天消耗了多少咖啡吗？找到你的热情所在，并将你新学到的 JavaScript 概念应用到那里。概念是相同的，应用是不同的。

1.  订阅来自你感兴趣领域的新闻简报和邮件列表。你会惊讶于每封邮件每天或每周都能获取到的信息量。这有助于你保持警惕，你可以及时了解最新的技术。

1.  写一篇博客（甚至是 StackOverflow 的回答）来分享你所知道和学到的东西。当你把学到的东西写下来时，总是会有帮助的。有一天，你甚至可以用它来作为自己的参考。
