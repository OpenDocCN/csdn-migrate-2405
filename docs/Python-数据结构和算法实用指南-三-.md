# Python 数据结构和算法实用指南（三）

> 原文：[`zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d`](https://zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：哈希和符号表

我们之前已经看过**数组**和**列表**，其中项目按顺序存储并通过索引号访问。索引号对计算机来说很有效。它们是整数，因此快速且易于操作。但是，它们并不总是对我们很有效。例如，如果我们有一个地址簿条目，比如在索引号 56 处，那个数字并没有告诉我们太多。没有任何东西将特定联系人与数字 56 联系起来。使用索引值从列表中检索条目是困难的。

在本章中，我们将研究一种更适合这种问题的数据结构：字典。字典使用关键字而不是索引号，并以`（键，值）`对的形式存储数据。因此，如果该联系人被称为*James*，我们可能会使用关键字*James*来定位联系人。也就是说，我们不会通过调用*contacts [56]*来访问联系人，而是使用*contacts* `james`。

字典是一种广泛使用的数据结构，通常使用哈希表构建。顾名思义，哈希表依赖于一种称为**哈希**的概念。哈希表数据结构以`键/值`对的方式存储数据，其中键是通过应用哈希函数获得的。它以非常高效的方式存储数据，因此检索速度非常快。我们将在本章讨论所有相关问题。

我们将在本章涵盖以下主题：

+   哈希

+   哈希表

+   不同的元素功能

# 技术要求

除了需要在系统上安装 Python 之外，没有其他技术要求。这是本章讨论的源代码的 GitHub 链接：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter07)。

# 哈希

哈希是一个概念，当我们将任意大小的数据提供给函数时，我们会得到一个简化的小值。这个函数称为**哈希函数**。哈希使用一个哈希函数将给定的数据映射到另一个数据范围，以便新的数据范围可以用作哈希表中的索引。更具体地说，我们将使用哈希将字符串转换为整数。在本章的讨论中，我们使用字符串转换为整数，但它可以是任何其他可以转换为整数的数据类型。让我们看一个例子来更好地理解这个概念。我们想要对表达式`hello world`进行哈希，也就是说，我们想要得到一个数值，我们可以说*代表*该字符串。

我们可以使用`ord（）`函数获得任何字符的唯一序数值。例如，`ord（'f'）`函数给出 102。此外，要获得整个字符串的哈希值，我们只需对字符串中每个字符的序数进行求和。请参阅以下代码片段：

```py
>>> sum(map(ord, 'hello world'))
1116
```

对于整个`hello world`字符串获得的数值`1116`称为**字符串的哈希**。请参考以下图表，以查看导致哈希值`1116`的字符串中每个字符的序数值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/12710178-03f0-4efd-8f50-b84231ea4f63.png)

前面的方法用于获得给定字符串的哈希值，并且似乎运行良好。但是，请注意，我们可以更改字符串中字符的顺序，我们仍然会得到相同的哈希值；请参阅以下代码片段，我们对`world hello`字符串获得相同的哈希值：

```py
>>> sum(map(ord, 'world hello'))
1116
```

同样，对于`gello xorld`字符串，哈希值将是相同的，因为该字符串的字符的序数值之和将是相同的，因为`g`的序数值比`h`小 1，`x`的序数值比`w`大 1。请参阅以下代码片段：

```py
>>> sum(map(ord, 'gello xorld'))
1116
```

看一下下面的图表，我们可以观察到该字符串的哈希值再次为`1116`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/623ed462-1cfe-4b45-b619-692367501b52.png)

# 完美哈希函数

**完美哈希函数**是指我们为给定字符串（它可以是任何数据类型，这里我们现在限制讨论为字符串）得到唯一的哈希值。实际上，大多数哈希函数都是不完美的，并且会发生冲突。这意味着哈希函数给一个以上的字符串返回相同的哈希值；这是不希望的，因为完美哈希函数应该为一个字符串返回唯一的哈希值。通常，哈希函数需要非常快速，因此通常不可能创建一个为每个字符串返回唯一哈希值的函数。因此，我们接受这一事实，并且知道我们可能会遇到一些冲突，也就是说，两个或更多个字符串可能具有相同的哈希值。因此，我们尝试找到一种解决冲突的策略，而不是试图找到一个完美的哈希函数。

为了避免前面示例中的冲突，我们可以例如添加一个乘数，使得每个字符的序数值乘以一个随着字符串进展而不断增加的值。接下来，通过添加每个字符的乘以序数值来获得字符串的哈希值。为了更好地理解这个概念，请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/a488b9e9-4cb8-4039-8c67-4954d1527d26.png)

在上图中，每个字符的序数值逐渐乘以一个数字。请注意，最后一行是值的乘积结果；第二行是每个字符的序数值；第三行显示乘数值；第四行通过将第二行和第三行的值相乘得到值，因此 `104 x 1` 等于 `104`。最后，我们将所有这些乘积值相加，得到 `hello world` 字符串的哈希值，即 `6736`。

这个概念的实现如下函数所示：

```py
    def myhash(s): 
        mult = 1 
        hv = 0 
        for ch in s: 
            hv += mult * ord(ch) 
            mult += 1 
        return hv 
```

我们可以在下面显示的字符串上测试这个函数：

```py
for item in ('hello world', 'world hello', 'gello xorld'): 
        print("{}: {}".format(item, myhash(item))) 
```

运行此程序，我们得到以下输出：

```py
% python hashtest.py

hello world: 6736
world hello: 6616
gello xorld: 6742
```

我们可以看到，这一次对这三个字符串得到了不同的哈希值。但是，这并不是一个完美的哈希。让我们尝试字符串 `ad` 和 `ga`：

```py
% python hashtest.py

ad: 297
ga: 297
```

我们仍然得到两个不同字符串相同的哈希值。因此，我们需要制定一种解决这种冲突的策略。我们很快将看到这一点，但首先，我们将学习哈希表的实现。

# 哈希表

**哈希表**是一种数据结构，其中元素是通过关键字而不是索引号访问的，不同于**列表**和**数组**。在这种数据结构中，数据项以类似于字典的键/值对的形式存储。哈希表使用哈希函数来找到应该存储和检索元素的索引位置。这使我们能够快速查找，因为我们使用与键的哈希值对应的索引号。

哈希表数据结构中的每个位置通常称为**槽**或**桶**，可以存储一个元素。因此，形式为 `(key, value)` 的每个数据项将存储在哈希表中由数据的哈希值决定的位置上。例如，哈希函数将输入字符串名称映射到哈希值；`hello world` 字符串被映射到哈希值 92，找到哈希表中的一个槽位置。考虑以下图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b737f679-af81-47f6-ada2-c7beb23d6de8.png)

为了实现哈希表，我们首先创建一个类来保存哈希表项。这些项需要有一个键和一个值，因为我们的哈希表是一个 `{key-value}` 存储：

```py
    class HashItem: 
        def __init__(self, key, value): 
            self.key = key 
            self.value = value 
```

这为我们提供了一种非常简单的存储项的方法。接下来，我们开始研究哈希表类本身。像往常一样，我们从构造函数开始：

```py
    class HashTable: 
        def __init__(self): 
            self.size = 256 
            self.slots = [None for i in range(self.size)] 
            self.count = 0 
```

哈希表使用标准的 Python 列表来存储其元素。让我们将哈希表的大小设置为 256 个元素。稍后，我们将研究如何在开始填充哈希表时扩展哈希表的策略。我们现在将在代码中初始化一个包含 256 个元素的列表。这些是要存储元素的位置——插槽或桶。因此，我们有 256 个插槽来存储哈希表中的元素。最后，我们添加一个计数器，用于记录实际哈希表元素的数量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c5ea5ffe-6a97-4132-837e-830e98b472c1.png)

重要的是要注意表的大小和计数之间的区别。表的大小是指表中插槽的总数（已使用或未使用）。表的计数是指填充的插槽的数量，也就是已添加到表中的实际（键-值）对的数量。

现在，我们需要决定将我们的哈希函数添加到表中。我们可以使用相同的哈希函数，它返回字符串中每个字符的序数值的总和，稍作修改。由于我们的哈希表有 256 个插槽，这意味着我们需要一个返回 1 到 256 范围内的值的哈希函数（表的大小）。一个很好的方法是返回哈希值除以表的大小的余数，因为余数肯定是 0 到 255 之间的整数值。

哈希函数只是用于类内部的，所以我们在名称前面加下划线（`_`）来表示这一点。这是 Python 中用来表示某些东西是内部使用的正常约定。这是`hash`函数的实现：

```py
    def _hash(self, key): 
        mult = 1 
        hv = 0 
        for ch in key: 
            hv += mult * ord(ch) 
            mult += 1 
        return hv % self.size 
```

目前，我们假设键是字符串。我们将讨论如何稍后使用非字符串键。现在，`_hash()`函数将为字符串生成哈希值。

# 在哈希表中存储元素

要将元素存储在哈希表中，我们使用`put()`函数将它们添加到表中，并使用`get()`函数检索它们。首先，我们将看一下`put()`函数的实现。我们首先将键和值嵌入`HashItem`类中，然后计算键的哈希值。

这是`put`函数的实现，用于将元素存储在哈希表中：

```py
    def put(self, key, value): 
        item = HashItem(key, value) 
        h = self._hash(key) 
```

一旦我们知道键的哈希值，它将被用来找到元素应该存储在哈希表中的位置。因此，我们需要找到一个空插槽。我们从与键的哈希值对应的插槽开始。如果该插槽为空，我们就在那里插入我们的项。

但是，如果插槽不为空，并且项的键与当前键不同，那么我们就会发生冲突。这意味着我们有一个项的哈希值与表中先前存储的某个项相同。这就是我们需要想出一种处理冲突的方法的地方。

例如，在下面的图表中，**hello world**键字符串已经存储在表中，当一个新的字符串`world hello`得到相同的哈希值`92`时，就会发生冲突。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/6fc3a488-d225-45a8-aaec-63afa11aa0df.png)

解决这种冲突的一种方法是从冲突的位置找到另一个空插槽；这种冲突解决过程称为**开放寻址**。我们可以通过线性地查找下一个可用插槽来解决这个问题，方法是在发生冲突的前一个哈希值上加`1`。我们可以通过将键字符串中每个字符的序数值的总和加`1`来解决这个冲突，然后再除以哈希表的大小来获得哈希值。这种系统化的访问每个插槽的方式是解决冲突的线性方式，称为**线性探测**。

让我们考虑一个例子，如下图所示，以更好地理解我们如何解决这个冲突。密钥字符串`eggs`的哈希值是 51。现在，由于我们已经使用了这个位置来存储数据，所以发生了冲突。因此，我们在哈希值中添加 1，这是由字符串的每个字符的序数值的总和计算出来的，以解决冲突。因此，我们获得了这个密钥字符串的新哈希值来存储数据——位置 52。请参见以下图表和代码片段以进行此实现：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/343bdb1c-ac38-4fc1-a624-10dfbab473ec.png)

现在，考虑以下代码：

```py
    while self.slots[h] is not None: 
        if self.slots[h].key is key: 
            break 
        h = (h + 1) % self.size 
```

上述代码是用来检查槽是否为空，然后使用描述的方法获取新的哈希值。如果槽为空（这意味着槽以前包含`None`），则我们将计数增加一。最后，我们将项目插入到所需位置的列表中：

```py
    if self.slots[h] is None: 
        self.count += 1 
    self.slots[h] = item  
```

# 从哈希表中检索元素

要从哈希表中检索元素，将返回与密钥对应的存储值。在这里，我们将讨论检索方法的实现——`get()`方法。此方法将返回与给定密钥对应的表中存储的值。

首先，我们计算要检索的密钥的哈希值对应的值。一旦我们有了密钥的哈希值，我们就在哈希表的哈希值位置查找。如果密钥项与该位置处存储的密钥值匹配，则检索相应的`value`。如果不匹配，那么我们将 1 添加到字符串中所有字符的序数值的总和，类似于我们在存储数据时所做的操作，然后查看新获得的哈希值。我们继续查找，直到找到我们的密钥元素或者检查了哈希表中的所有槽。

考虑一个例子来理解以下图表中的概念，分为四步：

1.  我们计算给定密钥字符串`"egg"`的哈希值，结果为 51。然后，我们将此密钥与位置 51 处存储的密钥值进行比较，但不匹配。

1.  由于密钥不匹配，我们计算一个新的哈希值。

1.  我们查找新创建的哈希值位置 52 处的密钥；我们将密钥字符串与存储的密钥值进行比较，这里匹配，如下图所示。

1.  在哈希表中返回与此密钥值对应的存储值。请参见以下图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/a5db02a4-57a6-4528-ab70-45ebc3299844.png)

为了实现这个检索方法，即`get()`方法，我们首先计算密钥的哈希值。接下来，我们在表中查找计算出的哈希值。如果匹配，则返回相应的存储值。否则，我们继续查看描述的计算出的新哈希值位置。以下是`get()`方法的实现：

```py
def get(self, key): 
    h = self._hash(key)    # computer hash for the given key 
    while self.slots[h] is not None:
        if self.slots[h].key is key: 
            return self.slots[h].value 
        h = (h+ 1) % self.size 
    return None        
```

最后，如果在表中找不到密钥，则返回`None`。另一个很好的选择可能是在表中不存在密钥的情况下引发异常。

# 测试哈希表

为了测试我们的哈希表，我们创建`HashTable`并将一些元素存储在其中，然后尝试检索它们。我们还将尝试`get()`一个不存在的密钥。我们还使用了两个字符串`ad`和`ga`，它们发生了冲突，并且由我们的哈希函数返回了相同的哈希值。为了正确评估哈希表的工作，我们也会处理这个冲突，只是为了看到冲突是如何正确解决的。请参见以下示例代码：

```py
ht = HashTable() 
    ht.put("good", "eggs") 
    ht.put("better", "ham") 
    ht.put("best", "spam") 
    ht.put("ad", "do not") 
    ht.put("ga", "collide") 

    for key in ("good", "better", "best", "worst", "ad", "ga"): 
        v = ht.get(key) 
        print(v) 
```

运行上述代码返回以下结果：

```py
% python hashtable.py

eggs
ham
spam
None
do not
collide 
```

如您所见，查找`worst`密钥返回`None`，因为密钥不存在。`ad`和`ga`密钥也返回它们对应的值，显示它们之间的冲突得到了正确处理。

# 使用[]与哈希表

使用`put()`和`get()`方法看起来并不方便。然而，我们更希望能够将我们的哈希表视为列表，因为这样会更容易使用。例如，我们希望能够使用`ht["good"]`而不是`ht.get("good")`来从表中检索元素。

这可以很容易地通过特殊方法`__setitem__()`和`__getitem__()`来完成。请参阅以下代码：

```py
    def __setitem__(self, key, value): 
        self.put(key, value) 

    def __getitem__(self, key): 
        return self.get(key) 
```

现在，我们的测试代码将会是这样的：

```py
    ht = HashTable() 
    ht["good"] = "eggs" 
    ht["better"] = "ham" 
    ht["best"] = "spam" 
    ht["ad"] = "do not" 
    ht["ga"] = "collide" 

    for key in ("good", "better", "best", "worst", "ad", "ga"): 
        v = ht[key] 
        print(v) 

    print("The number of elements is: {}".format(ht.count)) 
```

请注意，我们还打印了已存储在哈希表中的元素数量，使用`count`变量。

# 非字符串键

在实时应用中，通常我们需要使用字符串作为键。然而，如果有必要，您可以使用任何其他 Python 类型。如果您创建自己的类并希望将其用作键，您需要重写该类的特殊`__hash__()`函数，以便获得可靠的哈希值。

请注意，您仍然需要计算哈希值的模运算(`%`)和哈希表的大小以获取插槽。这个计算应该在哈希表中进行，而不是在键类中，因为表知道自己的大小（键类不应该知道它所属的表的任何信息）。

# 扩大哈希表

在我们的示例中，我们将哈希表的大小固定为 256。很明显，当我们向哈希表添加元素时，我们将开始填满空插槽，而在某个时刻，所有插槽都将被填满，哈希表将变满。为了避免这种情况，我们可以在表开始变满时扩大表的大小。

为了扩大哈希表的大小，我们比较表中的大小和计数。`size`是插槽的总数，`count`表示包含元素的插槽的数量。因此，如果`count`等于`size`，这意味着我们已经填满了表。哈希表的负载因子通常用于扩展表的大小；这给了我们一个关于表中有多少可用插槽被使用的指示。哈希表的负载因子通过将表中**已使用**的插槽数量除以表中的**总**插槽数量来计算。它的定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ee3e4e63-871f-4f89-9bfe-83df85d4fe6a.png)

当负载因子接近 1 时，这意味着表即将被填满，我们需要扩大表的大小。最好在表几乎填满之前扩大表的大小，因为当表填满时，从表中检索元素会变慢。负载因子为 0.75 可能是一个不错的值，用来扩大表的大小。

下一个问题是我们应该将表的大小增加多少。一种策略是简单地将表的大小加倍。

# 开放寻址

我们在示例中使用的冲突解决机制是线性探测，这是一种开放寻址策略的例子。线性探测很简单，因为我们使用了固定数量的插槽。还有其他开放寻址策略，它们都共享一个思想，即存在一个插槽数组。当我们想要插入一个键时，我们会检查插槽是否已经有项目。如果有，我们会寻找下一个可用的插槽。

如果我们有一个包含 256 个插槽的哈希表，那么 256 就是哈希表中元素的最大数量。此外，随着负载因子的增加，查找新元素的插入点将需要更长的时间。

由于这些限制，我们可能更喜欢使用不同的策略来解决冲突，比如链接法。

# 链接法

链接是处理哈希表中冲突问题的另一种方法。它通过允许哈希表中的每个插槽存储在冲突位置的多个项目的引用来解决这个问题。因此，在冲突的索引处，我们可以在哈希表中存储多个项目。观察以下图表——字符串**hello world**和**world hello**发生冲突。在链接的情况下，这两个项目都被允许存储在哈希值为**92**的位置上，使用一个**列表**。以下是用于显示使用链接解决冲突的示例图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/46886635-c11e-45e1-bc94-291c680dc461.png)

在链接中，哈希表中的插槽被初始化为空列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3518632e-5693-470a-87b0-0e6428fe8e49.png)

当插入一个元素时，它将被追加到与该元素的哈希值对应的列表中。也就是说，如果您有两个具有哈希值`1075`的元素，这两个元素都将被添加到哈希表的`1075%256=51`插槽中存在的列表中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d4084896-ca8c-4213-8e75-455df499452e.png)

前面的图表显示了具有哈希值`51`的条目列表。

然后通过链接避免冲突，允许多个元素具有相同的哈希值。因此，哈希表中可以存储的元素数量没有限制，而在线性探测的情况下，我们必须固定表的大小，当表填满时需要后续增长，这取决于负载因子。此外，哈希表可以容纳比可用插槽数量更多的值，因为每个插槽都包含一个可以增长的列表。

然而，在链接中存在一个问题——当列表在特定的哈希值位置增长时，它变得低效。由于特定插槽有许多项目，搜索它们可能会变得非常缓慢，因为我们必须通过列表进行线性搜索，直到找到具有我们想要的键的元素。这可能会减慢检索速度，这是不好的，因为哈希表的目的是高效的。以下图表演示了通过列表项进行线性搜索，直到找到匹配项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c8def2e4-1a3e-4b25-ba26-fbad0abbafbb.png)

因此，当哈希表中的特定位置具有许多条目时，检索项目的速度会变慢。可以通过在使用列表的位置上使用另一个数据结构来解决这个问题，该数据结构可以执行快速搜索和检索。使用**二叉搜索树**（**BSTs**）是一个不错的选择，因为它提供了快速检索，正如我们在前一章中讨论的那样。

我们可以简单地在每个插槽中放置一个（最初为空的）BST，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f33540e3-5074-4d55-9b5b-2ce497987b10.png)

在前面的图表中，`51`插槽包含一个 BST，我们使用它来存储和检索数据项。但我们仍然可能会遇到一个潜在的问题——根据将项目添加到 BST 的顺序，我们可能会得到一个与列表一样低效的搜索树。也就是说，树中的每个节点都只有一个子节点。为了避免这种情况，我们需要确保我们的 BST 是自平衡的。

# 符号表

符号表由编译器和解释器使用，用于跟踪已声明的符号并保留有关它们的信息。符号表通常使用哈希表构建，因为从表中高效地检索符号很重要。

让我们看一个例子。假设我们有以下 Python 代码：

```py
    name = "Joe" 
    age = 27 
```

在这里，我们有两个符号，`name`和`age`。它们属于一个命名空间，可以是`__main__`，但如果您将其放在那里，它也可以是模块的名称。每个符号都有一个`value`；例如，`name`符号的值是`Joe`，`age`符号的值是`27`。符号表允许编译器或解释器查找这些值。因此，`name`和`age`符号成为哈希表中的键。与它们关联的所有其他信息成为符号表条目的`value`。

不仅变量是符号，函数和类也被视为符号，并且它们也将被添加到符号表中，以便在需要访问它们时，可以从符号表中访问。例如，`greet()`函数和两个变量存储在以下图表中的符号表中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/58c18771-70c0-454c-91fc-514e05854547.png)

在 Python 中，每个加载的模块都有自己的符号表。符号表以该模块的名称命名。这样，模块就充当了命名空间。只要它们存在于不同的符号表中，我们可以拥有相同名称的多个符号，并且可以通过适当的符号表访问它们。请参见以下示例，显示程序中的多个符号表： 

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/161c04e4-7336-4910-8a73-47ec4d89feba.png)

# 总结

在本章中，我们研究了哈希表。我们研究了如何编写一个哈希函数将字符串数据转换为整数数据。然后，我们研究了如何使用哈希键快速高效地查找与键对应的值。

另外，我们还研究了哈希表实现中由于哈希值冲突而产生的困难。这导致我们研究了冲突解决策略，因此我们讨论了两种重要的冲突解决方法，即线性探测和链表法。

在本章的最后一节中，我们研究了符号表，它们通常是使用哈希表构建的。符号表允许编译器或解释器查找已定义的符号（如变量、函数或类）并检索有关它们的所有信息。

在下一章中，我们将讨论图和其他算法。


# 第八章：图和其他算法

在本章中，我们将讨论与图相关的概念。图的概念来自数学的一个分支，称为**图论**。图被用来解决许多计算问题。图是一种非线性数据结构。这种结构通过连接一组节点或顶点以及它们的边来表示数据。这与我们迄今为止所看到的数据结构非常不同，对图的操作（例如遍历）可能是非常规的。在本章中，我们将讨论与图相关的许多概念。此外，我们还将在本章后面讨论优先队列和堆。

到本章结束时，您应该能够做到以下几点：

+   了解图是什么

+   了解图的类型和它们的组成部分

+   了解如何表示图并遍历它

+   获得优先队列的基本概念

+   能够实现优先队列

+   能够确定列表中第 i 个最小的元素

# 技术要求

本章讨论的所有源代码都可以在以下链接的 GitHub 存储库中找到：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter08)。

# 图

图是一组顶点和边，它们之间形成连接。在更正式的方法中，图**G**是一个顶点集*V*和边集**E**的有序对，以正式的数学符号表示为`G = (V, E)`。

这里给出了一个图的示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/05db308a-34cf-4ecf-90df-2798d1d0153d.png)

让我们讨论一些图的重要定义：

+   **节点或顶点**：图中的一个点或节点称为一个顶点，通常在图中用一个点表示。在前面的图中，顶点或节点是**A**、**B**、**C**、**D**和**E**。

+   **边**：这是两个顶点之间的连接。连接**A**和**B**的线是前面图中边的一个例子。

+   **循环**：当一个节点的边与自身相连时，该边形成一个循环。

+   **顶点的度**：一个给定顶点上的边的总数被称为该顶点的度。例如，前面图中**B**顶点的度为`4`。

+   **邻接**：这指的是任意两个节点之间的连接；因此，如果两个顶点或节点之间有连接，则它们被称为相邻。例如，**C**节点与**A**节点相邻，因为它们之间有一条边。

+   **路径**：任意两个节点之间的顶点和边的序列表示从**A**节点到**B**节点的路径。例如，**CABE**表示从**C**节点到**E**节点的路径。

+   **叶节点**（也称为*挂节点*）：如果一个顶点或节点的度为 1，则称为叶节点或挂节点。

# 有向和无向图

图由节点之间的边表示。连接边可以被认为是有向的或无向的。如果图中的连接边是无向的，则图被称为无向图，如果图中的连接边是有向的，则它被称为有向图。无向图简单地将边表示为节点之间的线。除了它们相互连接之外，关于节点之间关系的其他信息都没有。例如，在下图中，我们展示了一个由四个节点**A**、**B**、**C**和**D**组成的无向图，它们之间通过边相连：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3b95d068-1a3e-4396-a06e-ccb8d3212bc8.png)

在有向图中，边提供了有关图中任意两个节点之间连接方向的信息。如果从节点**A**到**B**的边是有向的，那么边（**A**，**B**）就不等于边（**B**，**A**）。有向边用带箭头的线表示，箭头指向边连接两个节点的方向。例如，在下图中，我们展示了一个有向图，其中许多节点使用有向边连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2a0b4a49-1e7d-4191-9261-ec2f3631e0c8.png)

边的箭头确定了方向的流动。如前图所示，只能从**A**到**B**，而不能从**B**到**A**。在有向图中，每个节点（或顶点）都有一个入度和一个出度。让我们来看看这些是什么：

+   **入度**：进入图中一个顶点的边的总数称为该顶点的入度。例如，在前面的图中，**E**节点由于边**CE**进入，所以入度为`1`。

+   **出度**：从图中一个顶点出去的边的总数称为该顶点的出度。例如，在前面的图中，**E**节点的出度为`2`，因为它有两条边**EF**和**ED**出去。

+   **孤立顶点**：当一个节点或顶点的度为零时，称为孤立顶点。

+   **源顶点**：如果一个顶点的入度为零，则称为源顶点。例如，在前面的图中，**A**节点是源顶点。

+   **汇点**：如果一个顶点的出度为零，则称为汇点。例如，在前面的图中，**F**节点是汇点。

# 加权图

加权图是一个在图中的边上关联了数值权重的图。它可以是有向图，也可以是无向图。这个数值可以用来表示距离或成本，取决于图的目的。让我们来考虑一个例子。下图表示了从**A**节点到**D**节点的不同路径。你可以直接从**A**到**D**，也可以选择经过**B**和**C**，考虑到每条边的关联权重是到达下一个节点所需的时间（以分钟为单位）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/16b1ee37-e5b6-4d4e-951c-7dfd2bcf24ba.png)

在这个例子中，**AD**和**ABCD**代表两条不同的路径。路径就是在两个节点之间通过的一系列边。跟随这些路径，你会发现**AD**需要**40**分钟，而**ABCD**只需要**25**分钟。如果唯一关心的是时间，那么沿着**ABCD**路径旅行会更好，即使它可能是一条更长的路线。这里要记住的是边可以是有方向的，并且可能包含其他信息（例如所需时间、要行驶的距离等）。

我们可以以类似的方式实现图形，就像我们对其他数据结构（如链表）所做的那样。对于图形来说，将边看作对象和节点一样是有意义的。就像节点一样，边也可以包含额外的信息，这使得跟随特定路径成为必要。图中的边可以用不同节点之间的链接来表示；如果图中有一个有向边，我们可以用一个箭头从一个节点指向另一个节点来实现它，这在节点类中很容易用`next`或`previous`、`parent`或`child`来表示。

# 图的表示

在 Python 中实现图时，可以用两种主要形式来表示。一种是使用邻接表，另一种是使用邻接矩阵。让我们考虑一个例子，如下图所示，为图开发这两种表示类型：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/56cf0157-d3c0-4cbc-96f5-106bf1595186.png)

# 邻接表

邻接列表存储所有节点，以及与它们在图中直接连接的其他节点。在图`G`中，两个节点`A`和`B`如果之间有直接连接，则称它们是相邻的。在 Python 中，使用`list`数据结构表示图。列表的索引可以用来表示图中的节点或顶点。

在每个索引处，将该顶点的相邻节点存储起来。例如，考虑以下对应于先前显示的示例图的邻接列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ef3c9ee0-ee1c-4d1b-bac9-7ac85ad81b87.png)

方框中的数字代表顶点。`0`索引代表图的`A`顶点，其相邻节点为`B`和`C`。`1`索引代表图的`B`顶点，其相邻节点为`E`、`C`和`A`。类似地，图的其他顶点`C`、`E`和`F`在索引`2`、`3`和`4`处表示，其相邻节点如前图所示。

使用`list`进行表示相当受限制，因为我们缺乏直接使用顶点标签的能力。因此，使用`dictionary`数据结构更适合表示图。要使用`dictionary`数据结构实现相同的先前图，我们可以使用以下语句：

```py
    graph = dict() 
    graph['A'] = ['B', 'C'] 
    graph['B'] = ['E','C', 'A'] 
    graph['C'] = ['A', 'B', 'E','F'] 
    graph['E'] = ['B', 'C'] 
    graph['F'] = ['C'] 
```

现在我们可以很容易地确定**A**顶点的相邻顶点是**B**和**C**。**F**顶点的唯一邻居是**C**。同样，**B**顶点的相邻顶点是**E**、**B**和**A**。

# 邻接矩阵

图可以使用邻接矩阵表示的另一种方法是使用邻接矩阵。矩阵是一个二维数组。这里的想法是用`1`或`0`表示单元格，具体取决于两个顶点是否由边连接。我们在下图中演示了一个示例图，以及其对应的邻接矩阵：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/239d325d-3579-44fc-9574-51a29681914d.png)

可以使用给定的邻接列表来实现邻接矩阵。要实现邻接矩阵，让我们使用图的先前基于字典的实现。首先，我们必须获得邻接矩阵的关键元素。重要的是要注意，这些矩阵元素是图的顶点。我们可以通过对图的键进行排序来获得关键元素。此操作的代码片段如下：

```py
    matrix_elements = sorted(graph.keys()) 
    cols = rows = len(matrix_elements) 
```

接下来，使用图的键的长度来提供邻接矩阵的维度，这些维度存储在`cols`和`rows`中，`cols`和`rows`中的值相等。然后我们创建一个正确大小的空邻接矩阵，大小为`cols`乘以`rows`，并用零填充它。`edges_list`变量将存储图中形成边的元组。例如，A 和 B 节点之间的边将存储为`(A, B)`。初始化空邻接矩阵的代码片段如下：

```py
    adjacency_matrix = [[0 for x in range(rows)] for y in range(cols)] 
    edges_list = []
```

多维数组是使用嵌套的`for`循环填充的：

```py
    for key in matrix_elements: 
        for neighbor in graph[key]: 
            edges_list.append((key, neighbor)) 
```

顶点的邻居是通过`graph[key]`获得的。然后，结合`neighbor`使用`edges_list`存储创建的元组。

用于存储图的边的上述 Python 代码的输出如下：

```py
>>> [('A', 'B'), ('A', 'C'), ('B', 'E'), ('B', 'C'), ('B', 'A'), ('C', 'A'), 
 ('C', 'B'), ('C', 'E'), ('C', 'F'), ('E', 'B'), ('E', 'C'), 
 ('F', 'C')]
```

实现邻接矩阵的下一步是填充它，使用`1`表示图中存在边。这可以通过`adjacency_matrix[index_of_first_vertex][index_of_second_vertex] = 1`语句来完成。标记图的边存在的完整代码片段如下：

```py
    for edge in edges_list: 
        index_of_first_vertex = matrix_elements.index(edge[0]) 
        index_of_second_vertex = matrix_elements.index(edge[1]) 
        adjacency_matrix[index_of_first_vertex][index_of_second_vertex] = 1 
```

`matrix_elements`数组有它的`rows`和`cols`，从`A`到所有其他顶点，索引从`0`到`5`。`for`循环遍历我们的元组列表，并使用`index`方法获取要存储边的相应索引。

先前代码的输出是先前显示的示例图的邻接矩阵。生成的邻接矩阵如下所示：

```py
>>>
[0, 1, 1, 0, 0]
[1, 0, 0, 1, 0]
[1, 1, 0, 1, 1]
[0, 1, 1, 0, 0]
[0, 0, 1, 0, 0]
```

在第`1`行和第`1`列，`0`表示 A 和 A 之间没有边。同样，在第`2`列和第`3`行，有一个值为`1`，表示图中 C 和 B 顶点之间的边。

# 图遍历

图遍历意味着访问图的所有顶点，同时跟踪已经访问和尚未访问的节点或顶点。如果图遍历算法以最短可能的时间遍历图的所有节点，则该算法是高效的。图遍历的常见策略是沿着一条路径前进，直到遇到死胡同，然后向上遍历，直到遇到另一条路径。我们还可以迭代地从一个节点移动到另一个节点，以遍历整个图或部分图。图遍历算法在回答许多基本问题时非常重要——它们可以确定如何从图中的一个顶点到达另一个顶点，以及在图中从 A 到 B 顶点的哪条路径比其他路径更好。在接下来的部分中，我们将讨论两个重要的图遍历算法：**广度优先搜索**（**BFS**）和**深度优先搜索**（**DFS**）。

# 广度优先遍历

广度优先遍历算法以图的广度为基础工作。使用队列数据结构来存储要在图中访问的顶点的信息。我们从起始节点**A**开始。首先，我们访问该节点，然后查找它所有的相邻顶点。我们逐个访问这些相邻顶点，同时将它们的邻居添加到要访问的顶点列表中。我们一直遵循这个过程，直到访问了图的所有顶点，确保没有顶点被访问两次。

让我们通过以下图示例更好地理解图的广度优先遍历：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f707225d-efca-4c9e-be16-cd6a3bac6ff5.png)

在上图中，左侧有一个五个节点的图，右侧有一个队列数据结构，用于存储要访问的顶点。我们开始访问第一个节点**A**，然后将其所有相邻的顶点**B**、**C**和**E**添加到队列中。在这里，需要注意的是，添加相邻节点到队列有多种方式，因为有三个节点**B**、**C**和**E**，可以按照**BCE**、**CEB**、**CBE**、**BEC**或**ECB**的顺序添加到队列中，每种方式都会给出不同的树遍历结果。

图遍历的所有可能解决方案都是正确的，但在这个例子中，我们将按字母顺序添加节点。如图所示，访问了**A**节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/27150f8e-3c54-4124-95e2-52a1a5b48413.png)

一旦我们访问了**A**顶点，接下来，我们访问它的第一个相邻顶点**B**，并添加那些尚未添加到队列或未访问的相邻顶点。在这种情况下，我们需要将**D**顶点添加到队列中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3b782d49-aea9-4aa0-bccd-32be854c1741.png)

现在，在访问**B**顶点之后，我们访问队列中的下一个顶点**C**。然后，添加那些尚未添加到队列中的相邻顶点。在这种情况下，没有未记录的顶点，因此不需要进行任何操作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/cb98173e-c3f9-4254-ac75-cb3eefaa916e.png)

在访问**C**顶点之后，我们访问队列中的下一个顶点**E**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/a444bc08-d7ec-42e2-a6e7-32b1c06491c4.png)

同样，在访问**E**顶点之后，我们在最后一步访问**D**顶点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3e1093a8-d4a6-4d88-9140-2f5d5cb36f85.png)

因此，用于遍历上述图的 BFS 算法按照**A-B-C-E-D**的顺序访问顶点。这是上述图的 BFS 遍历的一种可能解决方案，但根据我们如何将相邻节点添加到队列中，我们可以得到许多可能的解决方案。

要学习 Python 中此算法的实现，让我们考虑另一个无向图的示例。考虑以下图表作为图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/dbc67290-a5cd-4ffe-835a-3e11ea10b056.png)

图的邻接列表如下：

```py
    graph = dict() 
    graph['A'] = ['B', 'G', 'D'] 
    graph['B'] = ['A', 'F', 'E'] 
    graph['C'] = ['F', 'H'] 
    graph['D'] = ['F', 'A'] 
    graph['E'] = ['B', 'G'] 
    graph['F'] = ['B', 'D', 'C'] 
    graph['G'] = ['A', 'E'] 
    graph['H'] = ['C'] 
```

要使用广度优先算法遍历此图，我们将使用队列。该算法创建一个列表来存储已访问的顶点，遍历过程中。我们将从 A 节点开始遍历。

A 节点被排队并添加到已访问节点列表中。然后，我们使用`while`循环来遍历图。在`while`循环中，A 节点被出队。它的未访问的相邻节点 B、G 和 D 按字母顺序排序并排队。队列现在包含 B、D 和 G 节点。这些节点也被添加到已访问节点列表中。此时，我们开始`while`循环的另一个迭代，因为队列不为空，这也意味着我们并没有真正完成遍历。

B 节点被出队。在其相邻节点 A、F 和 E 中，节点 A 已经被访问。因此，我们只按字母顺序排队 E 和 F 节点。然后，E 和 F 节点被添加到已访问节点列表中。

此时，我们的队列包含以下节点：D、G、E 和 F。已访问节点列表包含 A、B、D、G、E 和 F。

D 节点被出队，但它的所有相邻节点都已被访问，所以我们只需出队。队列前面的下一个节点是 G。我们出队 G 节点，但我们也发现它的所有相邻节点都已被访问，因为它们在已访问节点列表中。因此，G 节点也被出队。我们也出队 E 节点，因为它的所有节点也都已被访问。队列中现在只剩下 F 节点。

F 节点被出队，我们意识到它的相邻节点 B、D 和 C 中，只有 C 尚未被访问。然后，我们将 C 节点入队并添加到已访问节点列表中。然后，C 节点被出队。C 有 F 和 H 两个相邻节点，但 F 已经被访问，只剩下 H 节点。H 节点被入队并添加到已访问节点列表中。

最后一次`while`循环迭代将导致 H 节点被出队。它的唯一相邻节点 C 已经被访问。一旦队列完全为空，循环就会中断。

在图中遍历的输出是 A、B、D、G、E、F、C 和 H。

BFS 的代码如下：

```py
    from collections import deque 

    def breadth_first_search(graph, root): 
        visited_vertices = list() 
        graph_queue = deque([root]) 
        visited_vertices.append(root) 
        node = root 

        while len(graph_queue) > 0: 
            node = graph_queue.popleft() 
            adj_nodes = graph[node] 

            remaining_elements = 
                set(adj_nodes).difference(set(visited_vertices)) 
            if len(remaining_elements) > 0: 
                for elem in sorted(remaining_elements): 
                    visited_vertices.append(elem) 
                    graph_queue.append(elem) 

        return visited_vertices 
```

当我们想要找出一组节点是否在已访问节点列表中时，我们使用`remaining_elements = set(adj_nodes).difference(set(visited_vertices))`语句。这使用`set`对象的`difference`方法来找到在`adj_nodes`中但不在`visited_vertices`中的节点。

在最坏的情况下，每个顶点或节点和边都将被遍历，因此 BFS 算法的时间复杂度为`O(|V| + |E|)`，其中`|V|`是顶点或节点的数量，而`|E|`是图中的边的数量。

# 深度优先搜索

正如其名称所示，DFS 算法在遍历广度之前，会先遍历图中任何特定路径的深度。因此，首先访问子节点，然后是兄弟节点。使用栈数据结构来实现 DFS 算法。

我们从访问 A 节点开始，然后查看 A 顶点的邻居，然后是邻居的邻居，依此类推。让我们在 DFS 的上下文中考虑以下图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ed6faf7a-b221-4000-bd58-91e6cf00c945.png)

访问完 A 顶点后，我们访问其邻居之一，B，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ec27341d-6a80-4b5d-a952-8fac290a5ae0.png)

访问完 B 顶点后，我们查看 A 的另一个邻居 S，因为没有与 B 相连的顶点可以访问。接下来，我们查看 S 顶点的邻居，即 C 和 G 顶点。我们访问 C 如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/fe9f9af7-5783-4f10-bf19-af222854d129.png)

访问**C**节点后，我们访问其相邻的**D**和**E**节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/6c2139c7-20f9-4d2f-9027-4e972e122b5c.png)

类似地，访问**E**顶点后，我们访问**H**和**F**顶点，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b063f8a5-beec-41da-bd2b-73bf9bec1cc9.png)

最后，我们访问**F**节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bded1b28-229f-4a15-a99b-50dc72925357.png)

DFS 遍历的输出是**A-B-S-C-D-E-H-G-F**。

为了实现 DFS，我们从给定图的邻接表开始。以下是先前图的邻接表：

```py
graph = dict() 
    graph['A'] = ['B', 'S'] 
    graph['B'] = ['A'] 
    graph['S'] = ['A','G','C'] 
    graph['D'] = ['C'] 
    graph['G'] = ['S','F','H'] 
    graph['H'] = ['G','E'] 
    graph['E'] = ['C','H'] 
    graph['F'] = ['C','G'] 
    graph['C'] = ['D','S','E','F'] 
```

DFS 算法的实现始于创建一个列表来存储已访问的节点。`graph_stack`栈变量用于辅助遍历过程。我们使用普通的 Python 列表作为栈。起始节点称为`root`，并与图的邻接矩阵`graph`一起传递。`root`被推入栈中。`node = root`保存栈中的第一个节点：

```py
    def depth_first_search(graph, root): 
        visited_vertices = list() 
        graph_stack = list() 

        graph_stack.append(root) 
        node = root 
```

只要栈不为空，`while`循环的主体将被执行。如果`node`不在已访问节点列表中，我们将其添加。通过`adj_nodes = graph[node]`收集`node`的所有相邻节点。如果所有相邻节点都已经被访问，我们将从栈中弹出该节点，并将`node`设置为`graph_stack[-1]`。`graph_stack[-1]`是栈顶的节点。`continue`语句跳回到`while`循环的测试条件的开始。

```py
        while len(graph_stack) > 0: 
            if node not in visited_vertices: 
                visited_vertices.append(node) 
            adj_nodes = graph[node] 
            if set(adj_nodes).issubset(set(visited_vertices)): 
                graph_stack.pop() 
                if len(graph_stack) > 0: 
                    node = graph_stack[-1] 
                continue 
                else: 
                    remaining_elements =                                
                    set(adj_nodes).difference(set(visited_vertices)) 

            first_adj_node = sorted(remaining_elements)[0] 
            graph_stack.append(first_adj_node) 
            node = first_adj_node 
        return visited_vertices 
```

另一方面，如果并非所有相邻节点都已经被访问，则通过使用`remaining_elements = set(adj_nodes).difference(set(visited_vertices))`语句找到`adj_nodes`和`visited_vertices`之间的差异来获得尚未访问的节点。

`sorted(remaining_elements)`中的第一个项目被分配给`first_adj_node`，并推入栈中。然后我们将栈的顶部指向这个节点。

当`while`循环结束时，我们将返回`visited_vertices`。

现在我们将通过将其与先前的示例相关联来解释源代码的工作。**A**节点被选择为我们的起始节点。**A**被推入栈中，并添加到`visisted_vertices`列表中。这样做时，我们将其标记为已访问。`graph_stack`栈使用简单的 Python 列表实现。我们的栈现在只有 A 作为其唯一元素。我们检查**A**节点的相邻节点**B**和**S**。为了测试**A**的所有相邻节点是否都已经被访问，我们使用`if`语句：

```py
    if set(adj_nodes).issubset(set(visited_vertices)): 
        graph_stack.pop() 
        if len(graph_stack) > 0: 
            node = graph_stack[-1] 
        continue 
```

如果所有节点都已经被访问，我们将弹出栈顶。如果`graph_stack`栈不为空，我们将栈顶的节点赋给`node`，并开始另一个`while`循环主体的执行。如果`set(adj_nodes).issubset(set(visited_vertices))`语句评估为`True`，则表示`adj_nodes`中的所有节点都是`visited_vertices`的子集。如果`if`语句失败，这意味着还有一些节点需要被访问。我们通过`remaining_elements = set(adj_nodes).difference(set(visited_vertices))`获得这些节点的列表。

参考图表，**B**和**S**节点将被存储在`remaining_elements`中。我们将按照字母顺序访问列表，如下所示：

```py
    first_adj_node = sorted(remaining_elements)[0] 
    graph_stack.append(first_adj_node) 
    node = first_adj_node
```

我们对`remaining_elements`进行排序，并将第一个节点返回给`first_adj_node`。这将返回**B**。我们通过将其附加到`graph_stack`来将**B**节点推入栈。我们通过将其分配给`node`来准备访问**B**节点。

在`while`循环的下一次迭代中，我们将**B**节点添加到`visited nodes`列表中。我们发现**B**的唯一相邻节点**A**已经被访问。因为**B**的所有相邻节点都已经被访问，我们将其从栈中弹出，只留下**A**作为栈中的唯一元素。我们返回到**A**，检查它的所有相邻节点是否都已经被访问。**A**节点现在只有**S**节点是未访问的。我们将**S**推入栈中，然后重新开始整个过程。

遍历的输出是`A-B-S-C-D-E-H-G-F`。

深度优先搜索在解决迷宫问题、查找连通分量和查找图的桥梁等方面有应用。

# 其他有用的图方法

我们经常需要使用图来找到两个节点之间的路径。有时，需要找到节点之间的所有路径，在某些情况下，我们可能需要找到节点之间的最短路径。例如，在路由应用中，我们通常使用各种算法来确定从源节点到目标节点的最短路径。对于无权图，我们只需确定它们之间边数最少的路径。如果给定了加权图，我们必须计算通过一组边的总权重。

因此，在不同的情况下，我们可能需要使用不同的算法来找到最长或最短的路径。

# 优先队列和堆

优先队列是一种类似于队列和栈数据结构的数据结构，它存储与其关联的优先级的数据。在优先队列中，具有最高优先级的项目首先被服务。优先队列通常使用堆来实现，因为对于这个目的来说它非常高效；然而，它也可以使用其他数据结构来实现。它是一个修改过的队列，以最高优先级的顺序返回项目，而队列则以添加项目的顺序返回项目。优先队列在许多应用中使用，例如 CPU 调度。

让我们举个例子来演示优先队列比普通队列的重要性。假设在商店里，顾客排队等候服务只能在队列的前端进行。每个顾客在得到服务之前都会在队列中花费一些时间。如果四个顾客在队列中花费的时间分别是 4、30、2 和 1，那么队列中的平均等待时间就变成了`(4 + 34 + 36 + 37)/4`，即`27.75`。然而，如果我们将优先条件与队列中存储的数据关联起来，那么我们可以给予花费时间最少的顾客更高的优先级。在这种情况下，顾客将按照花费时间的顺序进行服务，即按照 1、2、4、30 的顺序。因此，平均等待时间将变为`(1 + 3 + 7 + 37)/4`，现在等于`12`——一个更好的平均等待时间。显然，按照花费时间最少的顾客进行服务是有益的。按照优先级或其他标准选择下一个项目的方法是创建优先队列的基础。优先队列通常使用堆来实现。

堆是满足堆属性的数据结构。堆属性规定父节点和其子节点之间必须存在一定的关系。这个属性必须在整个堆中都适用。

在最小堆中，父节点和子节点之间的关系是父节点的值必须始终小于或等于其子节点的值。由于这个关系，堆中最小的元素必须是根节点。

另一方面，在最大堆中，父节点大于或等于其子节点。由此可知，最大值组成了根节点。

堆是二叉树，尽管我们将使用二叉树，但实际上我们将使用列表来表示它。堆存储完全二叉树。完全二叉树是指在开始填充下一行之前，每一行必须完全填满，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/1cc995f2-9454-47c1-9f92-c16a8b884182.png)

为了使索引的数学运算更容易，我们将把列表中的第一项（索引 0）留空。之后，我们将树节点按照从上到下、从左到右的顺序放入列表中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8ddea893-9e46-4226-9160-4fcdd911daef.png)

如果你仔细观察，你会注意到你可以很容易地检索到任何节点的子节点在`n`索引。左子节点位于`2n`，右子节点位于`2n + 1`。这总是成立的。例如，C 节点将位于`3`索引，因为 C 是 A 节点的右子节点，其索引为`1`，所以它变成了`2n+1 = 2*1 + 1 = 3`。

让我们讨论使用 Python 实现最小堆，因为一旦我们理解了最小堆，实现最大堆将更加直接。我们从堆类开始，如下所示：

```py
     class Heap: 
        def __init__(self): 
            self.heap = [0] 
            self.size = 0 
```

我们用零初始化堆列表，以表示虚拟的第一个元素（记住我们只是为了简化数学而这样做）。我们还创建一个变量来保存堆的大小。这并不是必要的，因为我们可以检查列表的大小，但我们总是需要记住将其减少一。因此，我们选择保持一个单独的变量。

# 插入操作

向最小堆插入项目需要分两步进行。首先，我们将新元素添加到列表的末尾（我们理解为树的底部），并将堆的大小增加一。其次，在每次插入操作之后，我们需要将新元素在堆树中安排起来，以使所有节点以满足堆属性的方式组织。这是为了提醒我们，最小堆中最小的元素需要是根元素。

我们首先创建一个名为`arrange`的辅助方法，它负责在插入后安排所有节点。让我们考虑在最小堆中添加元素的示例。我们在下图中提供了一个示例堆，并希望在其中插入值为`2`的元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8bb8b3e5-192f-4127-92f1-d97d8a56fcf2.png)

新元素已经占据了第三行或级别的最后一个插槽。它的索引值为 7。现在我们将该值与其父节点进行比较。父节点的索引为`7/2 = 3`（整数除法）。该元素的值为 6，所以我们交换 2，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/1086030c-280d-4d34-bfa6-90f390182773.png)

我们的新元素已经被交换并移动到了**3**索引。我们还没有达到堆的顶部（*3/2 > 0*），所以我们继续。我们元素的新父节点位于索引*3/2=1*。所以我们再次比较，如果需要，再次交换：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/00545df1-f14c-4d8b-8d93-5120d5ab74d9.png)

最终交换后，我们得到了一个堆，如下所示。请注意，它符合堆的定义：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/53fadd7f-0c58-43a7-bdc3-f8ef93057166.png)

在我们向最小堆插入元素后，这是`arrange()`方法的实现：

```py
    def arrange(self, k): 
```

我们将循环直到达到根节点，这样我们就可以将元素安排到需要到达的最高位置。由于我们使用整数除法，一旦小于`2`，循环就会中断：

```py
        while k // 2 > 0: 
```

比较父节点和子节点。如果父节点大于子节点，则交换两个值：

```py
        if self.heap[k] < self.heap[k//2]: 
            self.heap[k], self.heap[k//2] = self.heap[k//2], 
            self.heap[k] 
```

最后，不要忘记向上移动树：

```py
        k //= 2 
```

这个方法确保元素被正确排序。

现在，我们只需要从我们的`insert`方法中调用这个方法：

```py
    def insert(self, item): 
        self.heap.append(item) 
        self.size += 1 
        self.arrange(self.size) 
```

请注意，`insert`中的最后一行调用`arrange()`方法来根据需要重新组织堆。

# 弹出操作

`pop`操作从堆中移除一个元素。从最小堆中移除元素的原因是，首先找出要删除的项目的索引，然后组织堆以满足堆属性。然而，更常见的是从最小堆中弹出最小值，并根据最小堆的属性，我们可以通过其根值获得最小值。因此，为了获取并从最小堆中删除最小值，我们移除根节点并重新组织堆的所有节点。我们还将堆的大小减少一。

然而，一旦根节点被弹出，我们就需要一个新的根节点。为此，我们只需取出列表中的最后一个项目，并将其作为新的根。也就是说，我们将它移动到列表的开头。然而，所选的最后一个节点可能不是堆中最小的元素，因此我们需要重新组织堆的节点。为了根据最小堆属性对所有节点进行结构化，我们遵循了与插入元素时使用的`arrange()`方法相反的策略。我们将最后一个节点作为新的根，然后让它根据需要向下移动（或下沉）。

让我们通过一个例子来帮助理解这个概念。首先，我们弹出`root`元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ea6a7355-42dc-44ce-b906-c8a74c6c2856.png)

如果我们选择移动根的一个子节点，我们将不得不弄清楚如何重新平衡整个树结构，这将更加复杂。因此，我们做一些非常有趣的事情。我们将列表中的最后一个元素移动到`root`元素的位置上；例如，在下面的堆示例中，最后一个元素**6**被放置在根位置上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/7e7ff95f-1917-4ab7-9a1f-4f2a2d53dbe6.png)

现在，这个元素显然不是堆中最小的。因此，我们需要将它下沉到堆中。首先，我们需要确定是向左还是向右子节点下沉。我们比较两个子节点，以便最小的元素将作为根下沉。在这个例子中，我们比较了根的两个子节点，即**5**和**3**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/1d633f27-44e6-47c9-acfb-7ccb19717cb0.png)

右子节点显然更小：它的索引是**3**，表示*根索引* 2 + 1*。我们继续将我们的新根节点与该索引处的值进行比较，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bc3c7d19-1995-4618-9569-e595be98aacc.png)

现在我们的节点已经下降到索引**3**。我们需要将其与较小的子节点进行比较。然而，现在我们只有一个子节点，所以我们不需要担心与哪个子节点进行比较（对于最小堆，它总是较小的子节点）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2dc6e0f7-7801-4991-b6f6-dd66f46dc674.png)

这里不需要交换。由于没有更多的行，我们不需要做其他事情。请注意，在完成`sink()`操作后，堆符合我们对堆的定义。

现在我们可以开始实现这个了。但在我们实现`sink()`方法之前，我们需要注意如何确定要与父节点进行比较的子节点。让我们将选择放在自己的小方法中，这样代码看起来会简单一些：

```py
    def minindex(self, k): 
```

我们可能会超出列表的末尾——如果是这样，我们返回左子节点的索引：

```py
        if k * 2 + 1 > self.size: 
            return k * 2 
```

否则，我们简单地返回两个子节点中较小的那个的索引：

```py
        elif self.heap[k*2] < self.heap[k*2+1]: 
            return k * 2 
        else: 
            return k * 2 + 1
```

现在我们可以创建`sink`函数。就像以前一样，我们将循环，以便我们可以将我们的元素下沉到需要的位置：

```py
    def sink(self, k): 
          while k*2 <- self.size: 
```

接下来，我们需要知道是要与左子节点还是右子节点进行比较。这就是我们使用`minindex()`函数的地方：

```py
            mi = self.minindex(k)
```

就像我们在插入操作中的`arrange()`方法中所做的那样，我们比较父节点和子节点，看看我们是否需要进行交换：

```py
            if self.heap[k] > self.heap[mi]: 
                self.heap[k], self.heap[mi] = self.heap[mi], 
                self.heap[k] 
```

我们需要确保向下移动树，这样我们就不会陷入循环中：

```py
            k = mi 
```

现在唯一剩下的就是实现主要的`pop()`方法本身。这非常简单，因为`sink()`方法执行了大部分工作：

```py
    def pop(self): 
        item = self.heap[1] 
        self.heap[1] = self.heap[self.size] 
        self.size -= 1 
        self.heap.pop() 
        self.sink(1) 
        return item
```

# 测试堆

现在，让我们测试堆的实现，并通过一个例子来讨论。我们首先通过逐个插入 10 个元素来构建一个堆。让元素为`{4, 8, 7, 2, 9, 10, 5, 1, 3, 6}`。首先，我们手动创建一个包含这些元素的堆，然后我们将实现它并验证我们是否做得正确：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/43b714fe-a272-4abf-8977-2404128f041b.png)

在上图中，我们展示了一个逐步插入元素到堆中的过程。在这里，我们继续按照所示添加元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f378b0d1-6ba0-4ad1-8c70-2fcd91194238.png)

最后，我们向堆中插入一个元素**6**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/73e8a792-fa08-4fc2-97e3-26ae969442a8.png)

现在，让我们开始创建堆并插入数据，如下所示的代码：

```py
    h = Heap() 
    for i in (4, 8, 7, 2, 9, 10, 5, 1, 3, 6): 
        h.insert(i) 
```

我们可以打印堆列表，只是为了检查元素的排序方式。如果你将其重新绘制为树结构，你会注意到它满足堆的所需属性，类似于我们手动创建的那样：

```py
    print(h.heap) 
```

现在我们将一个一个地弹出项目。注意项目是如何按照从低到高的顺序排序出来的。同时，注意每次`pop`后堆列表是如何改变的。`sink()`方法将重新组织堆中的所有项目：

```py
    for i in range(10): 
        n = h.pop() 
        print(n) 
        print(h.heap) 
```

在前面的部分中，我们讨论了使用最小堆的概念，因此通过简单地颠倒逻辑，实现最大堆应该是一个简单的任务。

我们将在第十章中再次使用我们在这里讨论的最小堆，*排序*，关于排序算法，并将重写列表中元素的排序代码。这些算法被称为堆排序算法。

# 选择算法

选择算法属于一类算法，旨在解决在列表中找到第 i 个最小元素的问题。当列表按升序排序时，列表中的第一个元素将是列表中最小的项。列表中的第二个元素将是列表中第二小的元素。列表中的最后一个元素将是最小的（或最大的）元素。

在创建堆数据结构时，我们已经了解到调用`pop`方法将返回最小堆中的最小元素。从最小堆中弹出的第一个元素是列表中的最小元素。同样，从最小堆中弹出的第七个元素将是列表中第七小的元素。因此，在列表中找到第 i 个最小元素将需要我们弹出堆 i 次。这是在列表中找到第 i 个最小元素的一种非常简单和高效的方法。

然而，在第十一章，*选择算法*中，我们将学习更多寻找列表中第 i 个最小元素的方法。

选择算法在过滤嘈杂数据、查找列表中的中位数、最小和最大元素等方面有应用，并且甚至可以应用在计算机国际象棋程序中。

# 总结

本章讨论了图和堆。图的主题对于许多现实世界的应用非常重要和有用。我们已经看过了用列表和字典表示图的不同方法。为了遍历图，我们使用了两种方法：BFS 和 DFS。

然后我们转向了堆和优先队列，以了解它们的实现。本章以使用堆的概念来查找列表中第 i 个最小元素的讨论结束。

下一章将引领我们进入搜索领域，以及我们可以有效搜索列表中项目的各种方法。


# 第九章：搜索

所有数据结构中最重要的操作之一是从存储的数据中搜索元素。有各种方法可以在数据结构中搜索元素；在本章中，我们将探讨可以用来在项目集合中查找元素的不同策略。

搜索操作对于排序非常重要。如果没有使用某种搜索操作的变体，几乎不可能对数据进行排序。如果搜索算法有效，排序算法将会很快。在本章中，我们将讨论不同的搜索算法。

搜索操作的性能受到即将搜索的项目是否已经排序的影响，我们将在后续章节中看到。

在本章结束时，您将能够做到以下事情：

+   了解各种搜索算法

+   了解流行搜索算法的实现

+   了解二分搜索算法的实现

+   了解插值的实现

# 技术要求

本章中使用的源代码可在以下 GitHub 链接找到：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.7-Second-Edition/tree/master/Chapter09`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.7-Second-Edition/tree/master/Chapter09)。

# 搜索简介

搜索算法分为两种类型：

+   将搜索算法应用于已经排序的项目列表；即应用于有序的项目集

+   将搜索算法应用于未排序的项目集

# 线性搜索

*搜索*操作是为了从存储的数据中找出给定的项目。如果存储的列表中存在搜索的项目，则返回其所在的索引位置，否则返回未找到该项目。在列表中搜索项目的最简单方法是线性搜索方法，其中我们在整个列表中逐个查找项目。

让我们以`5`个列表项`{60, 1, 88, 10, 11, 100}`为例，以了解线性搜索算法，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/03ac28e0-5e8e-46c6-89c4-92f96fb74625.png)

前面的列表中的元素可以通过列表索引访问。为了在列表中找到一个元素，我们使用线性搜索技术。该技术通过使用索引遍历元素列表，从列表的开头移动到末尾。每个元素都会被检查，如果它与搜索项不匹配，则会检查下一个项目。通过从一个项目跳到下一个项目，列表被顺序遍历。

本章中使用整数值的列表项来帮助您理解概念，因为整数可以很容易地进行比较；但是，列表项也可以保存任何其他数据类型。

# 无序线性搜索

线性搜索方法取决于列表项的存储方式-它们是否按顺序排序或无序存储。让我们首先看看列表是否包含未排序的项目。

考虑一个包含元素 60、1、88、10 和 100 的列表-一个无序列表。列表中的项目没有按大小排序。要在这样的列表上执行搜索操作，首先从第一个项目开始，将其与搜索项进行比较。如果搜索项不匹配，则检查列表中的下一个元素。这将继续进行，直到我们到达列表中的最后一个元素或找到匹配项为止。

以下是 Python 中对无序项目列表进行线性搜索的实现：

```py
    def search(unordered_list, term): 
       unordered_list_size = len(unordered_list) 
        for i in range(unordered_list_size): 
            if term == unordered_list[i]: 
                return i 

        return None 
```

`search`函数接受两个参数；第一个是保存我们数据的列表，第二个参数是我们正在寻找的项目，称为**搜索项**。

获取数组的大小并确定`for`循环执行的次数。以下代码描述了这一点：

```py
        if term == unordered_list[i]: 
            ... 
```

在`for`循环的每次通过中，我们测试搜索项是否等于索引项。如果为真，则表示匹配，无需继续搜索。我们返回在列表中找到搜索项的索引位置。

如果循环运行到列表的末尾而没有找到匹配项，则返回`None`，表示列表中没有这样的项目。

在无序的项目列表中，没有指导规则来插入元素。因此，它影响了搜索的执行方式。因此，我们必须依次访问列表中的所有项目。如下图所示，对术语**66**的搜索从第一个元素开始，并移动到列表中的下一个元素。

因此，首先将**60**与**66**进行比较，如果不相等，我们将**66**与下一个元素**1**进行比较，然后是**88**，依此类推，直到在列表中找到搜索项为止：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ba66df36-c90d-478a-a31d-9baa5b3407b0.png)

无序线性搜索的最坏情况运行时间为`O(n)`。在找到搜索项之前，可能需要访问所有元素。最坏情况是搜索项位于列表的最后位置。

# 有序线性搜索

线性搜索的另一种情况是，当列表元素已经排序时，我们的搜索算法可以得到改进。假设元素已按升序排序，则搜索操作可以利用列表的有序性使搜索更加高效。

算法简化为以下步骤：

1.  按顺序移动列表

1.  如果搜索项大于循环中当前检查的对象或项，则退出并返回`None`

在遍历列表的过程中，如果搜索项大于当前项，则无需继续搜索。

让我们考虑一个示例来看看这是如何工作的。我们拿一个项目列表，如下图所示，并且我们想搜索术语`5`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/409f41bf-abb5-425d-a412-05fa3f565249.png)

当搜索操作开始并且第一个元素与搜索项（**5**）进行比较时，找不到匹配项。但是，列表中还有更多元素，因此搜索操作继续检查下一个元素。在排序列表中继续前进的更有力的原因是，我们知道搜索项可能与大于**2**的任何元素匹配。

经过第四次比较，我们得出结论，搜索项无法在列表中后面的任何位置找到**6**所在的位置。换句话说，如果当前项大于搜索项，则表示无需进一步搜索列表。

以下是列表已排序时线性搜索的实现：

```py
    def search(ordered_list, term): 
        ordered_list_size = len(ordered_list) 
        for i in range(ordered_list_size): 
            if term == ordered_list[i]: 
                return i 
            elif ordered_list[i] > term: 
                return None 

        return None 
```

在上述代码中，`if`语句现在用于检查搜索项是否在列表中找到。`elif`测试条件为`ordered_list[i] > term`。如果比较结果为`True`，则该方法返回`None`。

方法中的最后一行返回`None`，因为循环可能会遍历列表，但搜索项仍未在列表中匹配。

有序线性搜索的最坏情况时间复杂度为`O(n)`。一般来说，这种搜索被认为是低效的，特别是在处理大型数据集时。

# 二进制搜索

二进制搜索是一种搜索策略，用于在**排序**的数组或列表中查找元素；因此，二进制搜索算法从给定的排序项目列表中找到给定的项目。这是一种非常快速和高效的搜索元素的算法，唯一的缺点是我们需要一个排序的列表。二进制搜索算法的最坏情况运行时间复杂度为`O(log n)`，而线性搜索的复杂度为`O(n)`。

二分搜索算法的工作方式如下。它通过将给定的列表分成两半来开始搜索项。如果搜索项小于中间值，则只在列表的前半部分查找搜索项，如果搜索项大于中间值，则只在列表的后半部分查找。我们重复相同的过程，直到找到搜索项或者我们已经检查了整个列表。

让我们通过一个例子来理解二分搜索。假设我们有一本 1000 页的书，我们想找到第 250 页。我们知道每本书的页码是从`1`开始顺序编号的。因此，根据二分搜索的类比，我们首先检查搜索项 250，它小于 500（书的中点）。因此，我们只在书的前半部分搜索所需的页面。然后我们再次看到书的前半部分的中点，即使用 500 页作为参考，我们找到中点，即 250。这使我们更接近找到第 250 页。然后我们在书中找到所需的页面。

让我们考虑另一个例子来理解二分搜索的工作原理。我们想从包含 12 个项的列表中搜索**43**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/692a7fab-d183-4d56-810f-b0ba163436cc.png)

我们通过将其与列表的中间项进行比较来开始搜索项，例如在示例中是**37**。如果搜索项小于中间值，则只查看列表的前半部分；否则，我们将查看另一半。因此，我们只需要在列表的后半部分搜索项。我们遵循相同的概念，直到在列表中找到搜索项**43**，如前图所示。

以下是对有序物品列表进行二分搜索算法的实现：

```py
def binary_search(ordered_list, term): 

    size_of_list = len(ordered_list) - 1 
    index_of_first_element = 0 
    index_of_last_element = size_of_list 
    while index_of_first_element <= index_of_last_element: 
        mid_point = (index_of_first_element + index_of_last_element)//2 
        if ordered_list[mid_point] == term: 
            return mid_point 
        if term > ordered_list[mid_point]: 
            index_of_first_element = mid_point + 1 
        else: 
            index_of_last_element = mid_point - 1 
    if index_of_first_element > index_of_last_element: 
        return None
```

假设我们要找到列表中**10**的位置如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c6fea9e7-dc50-4b14-a11a-c80121e372d0.png)

该算法使用`while`循环来迭代地调整列表中的限制，以便找到搜索项。停止`while`循环的终止条件是起始索引`index_of_first_element`和`index_of_last_element`索引之间的差值应为正数。

该算法首先通过将第一个元素的索引（**0**）加上最后一个元素的索引（**4**）并除以**2**来找到列表的中点，`mid_point`：

```py
mid_point = (index_of_first_element + index_of_last_element)//2 
```

在这种情况下，中点是`100`，值**10**不在列表的中间位置找到。由于我们正在搜索**10**，它小于中点，因此它位于列表的前半部分，因此，我们将索引范围调整为`index_of_first_element`到`mid_point-1`，如下图所示。然而，如果我们正在搜索**120**，在这种情况下，由于 120 大于中间值（100），我们将在列表的后半部分搜索项，并且我们需要将列表索引范围更改为`mid_point +1`到`index_of_last_element`。如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d775d66a-c695-499a-b072-9627fa419a4d.png)

现在我们的`index_of_first_element`和`index_of_last_element`的新索引分别为**0**和**1**，我们计算中点`(0 + 1)/2`，得到`0`。新的中点是**0**，因此我们找到中间项并将其与搜索项进行比较，`ordered_list[0]`，得到值**10**。现在我们找到了搜索项，并返回索引位置。

通过调整`index_of_first_element`和`index_of_last_element`的索引，我们将列表大小减半，只要`index_of_first_element`小于`index_of_last_element`。当这种情况不再成立时，很可能是我们要搜索的项不在列表中。

我们讨论的实现是迭代的。我们也可以通过应用相同的原则并移动标记搜索列表开头和结尾的指针来开发算法的递归变体。考虑以下代码：

```py
def binary_search(ordered_list, first_element_index, last_element_index, term): 

    if (last_element_index < first_element_index): 
        return None 
    else: 
        mid_point = first_element_index + ((last_element_index - first_element_index) // 2) 

        if ordered_list[mid_point] > term: 
            return binary_search(ordered_list, first_element_index, mid_point-1,term) 
        elif ordered_list[mid_point] < term: 
            return binary_search(ordered_list, mid_point+1, last_element_index, term) 
        else: 
            return mid_point 
```

对二分搜索算法的递归实现的调用及其输出如下：

```py
    store = [2, 4, 5, 12, 43, 54, 60, 77]
    print(binary_search(store, 0, 7, 2))   

Output:
>> 0
```

在这里，递归二分搜索和迭代二分搜索之间唯一的区别是函数定义，以及计算`mid_point`的方式。在`((last_element_index - first_element_index) // 2)`操作之后，`mid_point`的计算必须将其结果加到`first_element_index`上。这样，我们定义了尝试搜索的列表部分。

二分搜索算法的最坏情况时间复杂度为`O(log n)`。每次迭代中列表的一半遵循元素数量和它们的进展的`log(n)`。

不言而喻，`log x`假定是指以 2 为底的对数。

# 插值搜索

插值搜索算法是二分搜索算法的改进版本。当排序列表中的元素均匀分布时，它的性能非常高。在二分搜索中，我们总是从列表的中间开始搜索，而在插值搜索中，我们根据要搜索的项确定起始位置。在插值搜索算法中，起始搜索位置很可能最接近列表的开头或结尾，具体取决于搜索项。如果搜索项接近列表中的第一个元素，则起始搜索位置很可能靠近列表的开头。

插值搜索是二分搜索算法的另一种变体，与人类在任何项目列表上执行搜索的方式非常相似。它基于尝试猜测在排序项目列表中可能找到搜索项的索引位置。它的工作方式类似于二分搜索算法，只是确定分割标准以减少比较次数的方法不同。在二分搜索的情况下，我们将数据分成相等的两部分，在插值搜索的情况下，我们使用以下公式来分割数据：

```py
mid_point = lower_bound_index + (( upper_bound_index - lower_bound_index)// (input_list[upper_bound_index] - input_list[lower_bound_index])) * (search_value - input_list[lower_bound_index]) 
```

在上述公式中，`lower_bound_index`变量是下界索引，即列表中最小值的索引，`upper_bound_index`表示列表中最大值的索引位置。`input_list[lower_bound_index]`和`input_list[lower_bound_index]`变量分别是列表中的最小值和最大值。`search_term`变量包含要搜索的项的值。

让我们通过以下包含 7 个项目的列表来考虑一个示例，以了解插值搜索算法的工作原理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/69b60fe9-60b7-4ff4-a1c2-e7d5ed404713.png)

为了找到**120**，我们知道应该查看列表的右侧部分。我们对二分搜索的初始处理通常会首先检查中间元素，以确定是否与搜索项匹配。

更像人类的方法是选择一个中间元素，以便不仅将数组分成两半，而且尽可能接近搜索项。中间位置是使用以下规则计算的：

```py
mid_point = (index_of_first_element + index_of_last_element)//2 
```

在插值搜索算法的情况下，我们将用更好的公式替换这个公式，以使我们更接近搜索项。`mid_point`将接收`nearest_mid`函数的返回值，该值是使用以下方法计算的：

```py
def nearest_mid(input_list, lower_bound_index, upper_bound_index, search_value):

    return lower_bound_index + (( upper_bound_index -lower_bound_index)// (input_list[upper_bound_index] -input_list[lower_bound_index])) * (search_value -input_list[lower_bound_index]) 
```

`nearest_mid`函数的参数是要进行搜索的列表。`lower_bound_index`和`upper_bound_index`参数表示希望在列表中找到搜索项的范围。此外，`search_value`表示正在搜索的值。

给定我们的搜索列表，**44**，**60**，**75**，**100**，**120**，**230**和**250**，`nearest_mid`将使用以下值进行计算：

```py
lower_bound_index = 0
upper_bound_index = 6
input_list[upper_bound_index] = 250
input_list[lower_bound_index] = 44
search_value = 230
```

让我们计算`mid_point`的值：

```py
mid_point= 0 + (6-0)//(250-44) * (230-44)
         = 5 
```

现在可以看到`mid_point`的值将接收值`5`。因此，在插值搜索的情况下，算法将从索引位置`5`开始搜索，这是我们搜索词的位置索引。因此，要搜索的项将在第一次比较中找到，而在二分搜索的情况下，我们将选择**100**作为`mid_point`，这将需要再次运行算法。

以下是一个更直观的例子，说明了典型的二分搜索与插值搜索的不同之处。在典型的二分搜索中，它找到了看起来在列表中间的**中点**：

![可以看到**中点**实际上站在前面列表的大致中间。这是通过将列表分成两部分得到的结果。另一方面，在插值搜索的情况下，**中点**被移动到最有可能匹配项的位置：![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/fdb75873-7f16-4c81-bbe3-a62b392095ad.png)

在插值搜索中，**中点**通常更靠左或更靠右。这是由于在除法时使用的乘数的影响。在前面的图表中，我们的**中点**已经向右倾斜。

插值算法的实现与二分搜索的实现相同，只是我们计算**中点**的方式不同。

在这里，我们提供了插值搜索算法的实现，如下所示的代码：

```py
def interpolation_search(ordered_list, term): 

    size_of_list = len(ordered_list) - 1 

    index_of_first_element = 0 
    index_of_last_element = size_of_list 

    while index_of_first_element <= index_of_last_element: 
        mid_point = nearest_mid(ordered_list, index_of_first_element, index_of_last_element, term) 

        if mid_point > index_of_last_element or mid_point < index_of_first_element: 
            return None 

        if ordered_list[mid_point] == term: 
            return mid_point 

        if term > ordered_list[mid_point]: 
            index_of_first_element = mid_point + 1 
        else: 
            index_of_last_element = mid_point - 1 

    if index_of_first_element > index_of_last_element: 
        return None 
```

`nearest_mid`函数使用乘法运算。这可能会产生大于`upper_bound_index`或小于`lower_bound_index`的值。当发生这种情况时，意味着搜索词`term`不在列表中。因此，返回`None`表示这一点。

那么当`ordered_list[mid_point]`不等于搜索词时会发生什么呢？好吧，我们现在必须重新调整`index_of_first_element`和`index_of_last_element`，以便算法将专注于可能包含搜索词的数组部分。这与我们在二分搜索中所做的事情完全相同：

```py
if term > ordered_list[mid_point]: 
    index_of_first_element = mid_point + 1 
```

如果搜索词大于`ordered_list[mid_point]`存储的值，那么我们只需调整`index_of_first_element`变量，指向`mid_point + 1`索引。

以下图表显示了调整的过程。`index_of_first_element`被调整并指向`mid_point+1`索引：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b4d74ddb-972e-4f1b-8f31-404863c144c7.png)

图表只是说明了中点的调整。在插值搜索中，中点很少将列表分成两个完全相等的部分。

另一方面，如果搜索词小于`ordered_list[mid_point]`存储的值，那么我们只需调整`index_of_last_element`变量，指向索引`mid_point - 1`。这个逻辑在 if 语句的 else 部分中体现：`index_of_last_element = mid_point - 1`。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/62be8deb-9a92-4fcc-bb9a-29e33f89e048.png)

图表显示了对**index_of_last_element**的重新计算对**中点**位置的影响。

让我们用一个更实际的例子来理解二分搜索和插值搜索算法的内部工作原理。

例如，考虑以下元素列表：

```py
[ 2, 4, 5, 12, 43, 54, 60, 77] 
```

在索引 0 处存储值 2，在索引 7 处存储值 77。现在，假设我们要在列表中找到元素 2。这两种不同的算法将如何处理？

如果我们将这个列表传递给`interpolation search`函数，那么`nearest_mid`函数将使用`mid_point`计算公式返回等于`0`的值：

```py
mid_point= 0 + (7-0)//(77-2) * (2-2)
         = 0 
```

当我们得到`mid_point`值`0`时，我们从索引`0`开始插值搜索。只需一次比较，我们就找到了搜索项。

另一方面，二分搜索算法需要三次比较才能找到搜索项，如下图所示：

![

计算得到的第一个`mid_point`值为`3`。第二个`mid_point`值为`1`，最后一个`mid_point`值为搜索项所在的`0`。

因此，很明显，插值搜索算法在大多数情况下比二分搜索效果更好。

# 选择搜索算法

与有序和无序线性搜索函数相比，二分搜索和插值搜索算法在性能上更好。由于有序和无序线性搜索在列表中顺序探测元素以找到搜索项，因此其时间复杂度为`O(n)`。当列表很大时，性能非常差。

另一方面，二分搜索操作在每次搜索尝试时都会将列表切成两半。在每次迭代中，我们比线性策略更快地接近搜索项。时间复杂度为`O(log n)`。尽管使用二分搜索可以获得速度上的优势，但其主要缺点是不能应用于未排序的项目列表，也不建议用于小型列表，因为排序的开销很大。

能够到达包含搜索项的列表部分在很大程度上决定了搜索算法的性能。在插值搜索算法中，中点的计算方式使得更有可能更快地获得我们的搜索项。插值搜索的平均情况时间复杂度为`O(log(log n))`，而最坏情况时间复杂度为`O(n)`。这表明插值搜索比二分搜索更好，并在大多数情况下提供更快的搜索。

# 总结

在本章中，我们讨论了两种重要的搜索算法类型。讨论了线性和二分搜索算法的实现以及它们的比较。本章还详细讨论了二分搜索变体插值搜索。

在下一章中，我们将使用搜索算法的概念进行排序算法。我们还将利用已经获得的知识对项目列表执行排序算法。


# 第十章：排序

排序意味着重新组织数据，使其按从小到大的顺序排列。排序是数据结构和计算中最重要的问题之一。数据在排序之前经常被排序，因为这样可以非常高效地检索，无论是一组姓名、电话号码，还是简单待办事项清单上的项目。

在本章中，我们将学习一些最重要和流行的排序技术，包括以下内容：

+   冒泡排序

+   插入排序

+   选择排序

+   快速排序

+   堆排序

在本章中，我们通过考虑它们的渐近行为来比较不同的排序算法。一些算法相对容易开发，但性能可能较差，而其他算法在实现上稍微复杂一些，但在对长列表进行排序时表现良好。

排序后，对一组项目进行搜索操作变得更加容易。我们将从最简单的排序算法开始；即冒泡排序算法。

# 技术要求

用于解释本章概念的所有源代码都在以下 GitHub 存储库中提供：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter10)。

# 排序算法

排序意味着将列表中的所有项目按其大小的升序排列。我们将讨论一些最重要的排序算法，它们各自具有不同的性能属性，涉及运行时复杂性。排序算法根据它们的内存使用、复杂性、递归性以及它们是否基于比较等考虑进行分类。

一些算法使用更多的 CPU 周期，因此具有糟糕的渐近值。其他算法在对一些值进行排序时会消耗更多的内存和其他计算资源。另一个考虑因素是排序算法如何适合递归、迭代或两者表达。有些算法使用比较作为排序元素的基础。冒泡排序算法就是一个例子。非比较排序算法的例子包括桶排序和鸽巢排序算法。

# 冒泡排序算法

冒泡排序算法的思想非常简单。给定一个无序列表，我们比较列表中相邻的元素，每次比较后，将它们按大小顺序放置。这是通过交换相邻的项目来实现的，如果它们的顺序不正确。这个过程对于 n 个项目的列表会重复 n-1 次。在每次迭代中，最大的元素都会被放在最后。例如，在第一次迭代中，最大的元素将被放在列表的最后位置，然后，相同的过程将对剩下的 n-1 个项目进行。在第二次迭代中，第二大的元素将被放在列表的倒数第二个位置，然后该过程将重复，直到列表排序完成。

让我们以只有两个元素{5, 2}的列表来理解冒泡排序的概念，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/21f97a06-89a0-4128-a1e8-580c48e3d76b.png)

为了对这个列表进行排序，我们只需将值交换到正确的位置，**2** 占据索引**0**，**5** 占据索引**1**。为了有效地交换这些元素，我们需要一个临时存储区域：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/3e4f61f4-3eb8-413a-bbda-27ab37970caa.png)

冒泡排序算法的实现从交换方法开始，如前图所示。首先，元素**5**将被复制到临时位置`temp`。然后，元素**2**将被移动到索引**0**。最后，**5**将从 temp 移动到索引**1**。最终，元素将被交换。列表现在包含元素`[2, 5]`。以下代码将交换`unordered_list[j]`的元素与`unordered_list[j+1]`的元素，如果它们不按正确顺序排列的话：

```py
    temp = unordered_list[j] 
    unordered_list[j] = unordered_list[j+1] 
    unordered_list[j+1] = temp 
```

现在我们已经能够交换一个包含两个元素的数组，使用相同的思路对整个列表进行排序应该很简单。

让我们考虑另一个例子，以了解冒泡排序算法对包含**6**个元素的无序列表进行排序的工作原理，例如{**45**，**23**，**87**，**12**，**32**，**4**}。在第一次迭代中，我们开始比较前两个元素**45**和**23**，并交换它们，因为**45**应该放在**23**之后。然后，我们比较下一个相邻值**45**和**87**，看它们是否按正确顺序排列。如果它们没有按正确顺序排列，则交换它们。我们可以看到，在冒泡排序的第一次迭代后，最大的元素**87**被放置在列表的最后位置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/25605a4a-d41e-4ce3-826e-20fb3d1373c6.png)

第一次迭代后，我们只需要排列剩下的`(n-1)`个元素；我们通过比较剩下的五个元素的相邻元素来重复相同的过程。第二次迭代后，第二大的元素**45**被放置在列表中倒数第二个位置，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/da1be0d7-4d4c-4d22-aea5-5f96dee1e07c.png)

接下来，我们需要比较剩下的`(n-2)`个元素，将它们排列如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/87da0f01-1e66-4064-8810-5fcc9f1daa5e.png)

同样地，我们比较剩下的元素来对它们进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/4ccbf25c-3e8e-40f9-a2e7-9ec1141a3987.png)

最后，在剩下的两个元素中，我们将它们按正确顺序放置，以获得最终排序的列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/e9d0d690-e962-400f-8610-6b7c2519d5e8.png)

冒泡排序算法的实现将在一个双嵌套循环中工作，其中内部循环重复比较和交换给定列表中每次迭代中的相邻元素，而外部循环则跟踪内部循环应重复多少次。内部循环的实现如下：

```py
    for j in range(iteration_number): 
        if unordered_list[j] > unordered_list[j+1]: 
            temp = unordered_list[j] 
            unordered_list[j] = unordered_list[j+1] 
            unordered_list[j+1] = temp
```

在实现冒泡排序算法时，了解循环需要运行多少次才能完成所有交换是很重要的。例如，要对一个包含三个数字的列表`[3, 2, 1]`进行排序，我们最多需要交换两次元素。这等于列表长度减 1，可以写成`iteration_number = len(unordered_list)-1`。我们减 1 是因为它确切地给出了需要运行的最大迭代次数。让我们通过以下示例来展示这一点，在一个包含 3 个数字的列表中，通过在恰好两次迭代中交换相邻元素，最大的数字最终位于列表的最后位置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/97ed985d-c7fa-4bb3-9a07-2d3d831f886a.png)

`if`语句确保如果两个相邻元素已经按正确顺序排列，则不会发生不必要的交换。内部`for`循环只会导致相邻元素的交换在我们的列表中确切地发生两次。

为了使整个列表排序，这个交换操作需要发生多少次？我们知道，如果我们重复整个交换相邻元素的过程多次，列表将被排序。外部循环用于实现这一点。列表中元素的交换导致以下动态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/22b48f43-84eb-4f09-9156-a48f21eb1d6e.png)

我们意识到最多需要四次比较才能使我们的列表排序。因此，内部和外部循环都必须运行`len(unordered_list)-1`次，以便对所有元素进行排序，如下所示：

```py
iteration_number = len(unordered_list)-1 
    for i in range(iteration_number): 
        for j in range(iteration_number): 
            if unordered_list[j] > unordered_list[j+1]: 
                temp = unordered_list[j] 
                unordered_list[j] = unordered_list[j+1] 
                unordered_list[j+1] = temp
```

即使列表包含许多元素，也可以使用相同的原则。冒泡排序也有很多变体，可以最小化迭代和比较的次数。

例如，有一种冒泡排序算法的变体，如果在内部循环中没有交换，我们就会简单地退出整个排序过程，因为内部循环中没有任何交换操作表明列表已经排序。在某种程度上，这可以帮助加快算法的速度。

冒泡排序是一种低效的排序算法，其最坏情况和平均情况的运行时间复杂度为`O(n²)`，最佳情况的复杂度为`O(n)`。通常，不应该使用冒泡排序算法对大型列表进行排序。但是，在相对较小的列表上，它的性能还算不错。

# 插入排序算法

将相邻元素交换以对项目列表进行排序的想法也可以用于实现插入排序。插入排序算法维护一个始终排序的子列表，而列表的另一部分保持未排序。我们从未排序的子列表中取出元素，并将它们插入到排序的子列表的正确位置，使得这个子列表保持排序。

在插入排序中，我们从一个元素开始，假设它已经排序，然后从未排序的子列表中取出另一个元素，并将其放在排序的子列表中正确的位置（相对于第一个元素）。这意味着我们的排序子列表现在有两个元素。然后，我们再次从未排序的子列表中取出另一个元素，并将其放在排序的子列表中正确的位置（相对于已排序的两个元素）。我们反复遵循这个过程，将未排序的子列表中的所有元素一个接一个地插入到排序的子列表中。阴影元素表示有序子列表，在每次迭代中，未排序子列表中的一个元素被插入到排序子列表的正确位置。

让我们考虑一个例子来理解插入排序算法的工作原理。在我们的例子中，我们将对包含`6`个元素的列表`{45, 23, 87, 12, 32, 4}`进行排序。首先，我们从`1`个元素开始，假设它已经排序，然后从未排序的子列表中取出下一个元素`23`，并将其插入到排序的子列表中的正确位置。在下一次迭代中，我们从未排序的子列表中取出第三个元素`87`，并再次将其插入到排序的子列表中的正确位置。我们一直遵循相同的过程，直到所有元素都在排序的子列表中。整个过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/2be1efdb-8fd8-43d6-add6-aede489e3815.png)

为了理解插入排序算法的实现，让我们以另一个包含`5`个元素的示例列表`{5, 1, 100, 2, 10}`为例，并用详细的解释来检查这个过程。

让我们考虑以下数组：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/52c67297-48cb-4fb1-a6e6-863f02db06bb.png)

该算法通过使用`for`循环在**1**和**4**索引之间运行来开始。我们从索引**1**开始，因为我们假设索引**0**处的子数组已经按正确的顺序排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c140fcb5-08aa-4ad5-bafe-33fd12a82214.png)

在循环执行的开始，我们有以下内容：

```py
    for index in range(1, len(unsorted_list)): 
        search_index = index 
        insert_value = unsorted_list[index] 
```

在每次运行`for`循环的开始时，将`unsorted_list[index]`处的元素存储在`insert_value`变量中。稍后，当我们找到列表的排序部分中的适当位置时，`insert_value`将存储在该索引或位置上：

```py
    for index in range(1, len(unsorted_list)): 
        search_index = index 
        insert_value = unsorted_list[index] 

        while search_index > 0 and unsorted_list[search_index-1] > 
              insert_value : 
            unsorted_list[search_index] = unsorted_list[search_index-1] 
            search_index -= 1 

        unsorted_list[search_index] = insert_value 
```

`search_index`用于向`while`循环提供信息；也就是说，确切地找到下一个需要插入到排序子列表中的元素的位置。

`while`循环向后遍历列表，受两个条件的指导：首先，如果`search_index > 0`，那么意味着在列表的排序部分中还有更多的元素；其次，`while`循环运行时，`unsorted_list[search_index-1]`必须大于`insert_value`变量。`unsorted_list[search_index-1]`数组将执行以下操作之一：

+   在`while`循环第一次执行之前，指向`unsorted_list[search_index]`之前的一个元素

+   在`while`循环第一次运行后，指向`unsorted_list[search_index-1]`之前的一个元素

在我们的示例列表中，`while`循环将被执行，因为*5 > 1*。在`while`循环的主体中，`unsorted_list[search_index-1]`处的元素存储在`unsorted_list[search_index]`处。`search_index -= 1`将列表向后遍历，直到它的值为`0`。

我们的列表现在如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/86df775f-a6fb-4bd2-9b93-0038bbdc97dc.png)

在`while`循环退出后，`search_index`的最后已知位置（在这种情况下为`0`）现在帮助我们知道在哪里插入`insert_value`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ad028833-87aa-466e-8b28-8cb081f129b8.png)

在`for`循环的第二次迭代中，`search_index`的值将为**2**，这是数组中第三个元素的索引。此时，我们从左向右（朝向索引**0**）开始比较。**100**将与**5**进行比较，但因为**100**大于**5**，`while`循环不会执行。**100**将被替换为它自己，因为`search_index`变量从未被减少。因此，`unsorted_list[search_index] = insert_value`将不会产生影响。

当`search_index`指向索引**3**时，我们将**2**与**100**进行比较，并将**100**移动到存储**2**的位置。然后我们将**2**与**5**进行比较，并将**5**移动到最初存储**100**的位置。此时，`while`循环将中断，**2**将存储在索引**1**中。数组将部分排序，值为`[1, 2, 5, 100, 10]`。

前面的步骤将为列表最后一次发生。

插入排序算法被认为是稳定的，因为它不会改变具有相等键的元素的相对顺序。它也只需要消耗列表占用的内存，因为它是原地交换的。

插入排序算法的最坏情况运行时间复杂度为**`O(n²)`**，最佳情况复杂度为`O(n)`。

# 选择排序算法

另一个流行的排序算法是选择排序。选择排序算法首先找到列表中最小的元素，并将其与列表中的第一个位置存储的数据交换。因此，它使子列表排序到第一个元素。接下来，识别出剩余列表中最小的元素（即剩余列表中最小的元素），并将其与列表中的第二个位置交换。这使得初始的两个元素排序。该过程重复进行，列表中剩余的最小元素应该与列表中第三个索引处的元素交换。这意味着前三个元素现在已排序。这个过程重复了`(n-1)`次来对`n`个项目进行排序。

让我们通过一个示例来理解算法的工作原理。我们将使用选择排序算法对以下 4 个元素的列表进行排序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/00f7ef2b-0bcf-4184-995c-2bebd03c2d85.png)

从索引**0**开始，我们搜索列表中存在于索引**1**和最后一个元素索引之间的最小项。找到这个元素后，将其与索引**0**处的数据交换。我们只需重复此过程，直到列表完全排序。

在列表中搜索最小的项目是一个递增的过程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/11f39ec5-3839-4437-9724-52c16ca07749.png)

对元素**2**和**5**进行比较，选择**2**，因为它是这两个值中较小的值，因此这两个元素被交换。

交换操作后，数组如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/394c7330-7323-4726-88e1-bd3c7546399a.png)

此外，在索引**0**处，我们将**2**与**65**进行比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/09719f77-d0ec-4f7a-8a48-d1fd6609a8e6.png)

由于**65**大于**2**，这两个元素不会交换。在索引**0**处的元素**2**和索引**3**处的元素**10**之间进行了进一步比较。在这种情况下不会发生交换。当我们到达列表中的最后一个元素时，最小的元素将占据索引**0**。

在下一次迭代中，我们从索引**1**开始比较元素。我们重复整个过程，将索引**1**处存储的元素与从索引**2**到最后一个索引的所有元素进行比较。

第二次迭代从比较**5**和**65**开始，结果如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d4fd4df3-f7aa-4980-9d86-39af6d2d5108.png)

一旦我们发现**5**是从索引**1**到**3**的子列表中的最小值，我们将其放在索引**1**处。同样，从子列表**2**和**3**的索引中找到的下一个最小元素被放置在索引**3**处。

以下是选择排序算法的实现。函数的参数是我们想要按大小顺序排列的未排序项目列表：

```py
    def selection_sort(unsorted_list): 

        size_of_list = len(unsorted_list) 

        for i in range(size_of_list): 
            for j in range(i+1, size_of_list): 

                if unsorted_list[j] < unsorted_list[i]: 
                    temp = unsorted_list[i] 
                    unsorted_list[i] = unsorted_list[j] 
                    unsorted_list[j] = temp 
```

该算法通过使用外部`for`循环多次遍历列表`size_of_list`。因为我们将`size_of_list`传递给`range`方法，它将产生一个从**0**到`size_of_list-1`的序列。

内部循环负责遍历列表，并在遇到小于`unsorted_list[i]`指向的元素时交换元素。注意，内部循环从`i+1`开始，直到`size_of_list-1`。

内部循环从`i+1`开始搜索最小元素，但使用`j`索引：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/6a9bbfe0-c944-46d0-8109-daedd157611d.png)

前面的图表显示了算法搜索下一个最小项的方向。

选择排序算法的最坏情况和最佳情况运行时间复杂度均为`O(n2)`。

# 快速排序算法

快速排序算法对于排序非常有效。快速排序算法属于分治类算法，类似于归并排序算法，其中我们将问题分解为更简单的小块来解决。

# 列表分区

快速排序的概念是对给定的列表或数组进行分区。为了对列表进行分区，我们首先选择一个枢轴。列表中的所有元素将与此枢轴进行比较。在分区过程结束时，所有小于枢轴的元素将位于枢轴的左侧，而所有大于枢轴的元素将位于数组中枢轴的右侧。

# 枢轴选择

为了简单起见，我们将数组中的第一个元素作为枢轴。这种枢轴选择在性能上会下降，特别是在对已排序列表进行排序时。随机选择数组中间或最后一个元素作为枢轴并不会改善快速排序的性能。我们将在下一章讨论更好的选择枢轴和找到列表中最小元素的方法。

# 举例说明

在这个算法中，我们将一个未排序的数组分成两个子数组，使得分区点（也称为枢轴）左侧的所有元素都应该小于枢轴，而枢轴右侧的所有元素都应该大于枢轴。在快速排序算法的第一次迭代之后，选择的枢轴点被放置在列表中的正确位置。第一次迭代之后，我们得到两个无序的子列表，并在这两个子列表上再次执行相同的过程。因此，快速排序算法将列表分成两部分，并递归地在这两个子列表上应用快速排序算法以对整个列表进行排序。

我们首先选择一个枢轴点，所有项目都将与其进行比较，并在第一次迭代结束时，该值将被放置在有序列表中的正确位置。接下来，我们使用两个指针，一个左指针和一个右指针。左指针最初指向索引**1**处的值，右指针指向最后一个索引处的值。快速排序算法的主要思想是移动在枢轴值错误一侧的项目。因此，我们从左指针开始，从左到右移动，直到找到一个比枢轴值大的位置。类似地，我们将右指针向左移动，直到找到一个小于枢轴值的值。接下来，我们交换左右指针指示的这两个值。我们重复相同的过程，直到两个指针交叉；换句话说，右指针索引指示的值小于左指针索引的值时。

让我们以一个数字列表{**45**, **23**, **87**, **12**, **72**, **4**, **54**, **32**, **52**}为例，来理解快速排序算法的工作原理。假设我们列表中的枢轴点是第一个元素**45**。我们从索引**1**处向右移动左指针，并在找到值**87**时停止，因为（**87**>**45**）。接下来，我们将右指针向左移动，并在找到值**32**时停止，因为（**32**<**45**）。

现在，我们交换这两个值，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/7b232879-1527-4f8e-ac01-f56791cc7982.png)

之后，我们重复相同的过程，将左指针向右移动，并在找到值**72**时停止，因为（**72**>**45**）。接下来，我们将右指针向左移动，并在找到值**4**时停止，因为（**4**<**45**）。现在，我们交换这两个值，因为它们与枢轴值的方向相反。我们重复相同的过程，并在右指针索引值小于左指针索引值时停止。在这里，我们找到**4**作为分割点，并将其与枢轴值交换。如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/e05dddc1-22ab-495c-847c-b2765ed7d23c.png)

在快速排序算法的第一次迭代之后，可以观察到枢轴值**45**被放置在列表中的正确位置。

现在我们有了两个子列表：

1.  枢轴值**45**左侧的子列表具有小于**45**的值。

1.  枢轴值右侧的另一个子列表包含大于 45 的值。我们将在这两个子列表上递归应用快速排序算法，并重复此过程，直到整个列表排序完成。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/18334875-62fb-4170-bb9b-47f0b4b3a210.png)

# 实施

分区步骤对于理解快速排序算法的实现非常重要，因此我们将从实现分区开始进行检查。

让我们看另一个例子来理解实现。考虑以下整数列表。我们将使用分区函数对此列表进行分区，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/29b930cc-1cd7-4a9c-a5ba-54d2a951a9c5.png)

考虑以下代码：

```py
     def partition(unsorted_array, first_index, last_index): 

        pivot = unsorted_array[first_index] 
        pivot_index = first_index 
        index_of_last_element = last_index 

        less_than_pivot_index = index_of_last_element 
        greater_than_pivot_index = first_index + 1 
        ...
```

分区函数接收数组的第一个和最后一个元素的索引作为其参数，我们需要对其进行分区。

主元的值存储在`pivot`变量中，而其索引存储在`pivot_index`中。我们没有使用`unsorted_array[0]`，因为当调用未排序数组参数时，索引`0`不一定指向该数组中的第一个元素。主元的下一个元素的索引，即**左指针**，`first_index + 1`，标记了我们开始在数组中寻找大于主元的元素的位置，即`greater_than_pivot_index = first_index + 1`。**右指针**`less_than_pivot_index`变量指向`less_than_pivot_index = index_of_last_element`列表中最后一个元素的位置，我们从这里开始寻找小于主元的元素：

```py
    while True: 

        while unsorted_array[greater_than_pivot_index] < pivot and 
              greater_than_pivot_index < last_index: 
              greater_than_pivot_index += 1 

        while unsorted_array[less_than_pivot_index] > pivot and 
              less_than_pivot_index >= first_index: 
              less_than_pivot_index -= 1 
```

在执行主`while`循环的开始时，数组如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/16a3edea-4e3f-4532-82a8-500df977e3b9.png)

第一个内部`while`循环向右移动一个索引，直到落在索引**2**上，因为该索引处的值大于**43**。此时，第一个`while`循环中断并且不再继续。在第一个`while`循环的条件测试中，只有在`while`循环的测试条件评估为`True`时，才会评估`greater_than_pivot_index += 1`。这使得对大于主元的元素的搜索向右边的下一个元素进行。

第二个内部`while`循环每次向左移动一个索引，直到落在索引**5**上，其值**20**小于**43**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/5de935b0-20a7-4973-8819-81babd0768f0.png)

此时，内部的`while`循环都无法再执行：

```py
    if greater_than_pivot_index < less_than_pivot_index: 
        temp = unsorted_array[greater_than_pivot_index] 
            unsorted_array[greater_than_pivot_index] =    
                unsorted_array[less_than_pivot_index] 
            unsorted_array[less_than_pivot_index] = temp 
    else: 
        break
```

由于`greater_than_pivot_index < less_than_pivot_index`，`if`语句的主体交换了这些索引处的元素。`else`条件在任何时候`greater_than_pivot_index`变得大于`less_than_pivot_index`时打破无限循环。在这种情况下，这意味着`greater_than_pivot_index`和`less_than_pivot_index`已经交叉。

我们的数组现在如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b8479f3c-29f3-48f0-9807-ded22d7670e7.png)

当`less_than_pivot_index`等于**3**且`greater_than_pivot_index`等于**4**时，执行`break`语句。

一旦退出`while`循环，我们就会交换`unsorted_array[less_than_pivot_index]`处的元素和作为主元索引返回的`less_than_pivot_index`处的元素：

```py
    unsorted_array[pivot_index]=unsorted_array[less_than_pivot_index] 
    unsorted_array[less_than_pivot_index]=pivot 
    return less_than_pivot_index 
```

以下图表显示了代码在分区过程的最后一步中如何交换**4**和**43**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/31e49e1a-1589-4a9d-9404-1571133a1f64.png)

总之，第一次调用`quick_sort`函数时，它是围绕索引**0**的元素进行分区的。在分区函数返回后，我们得到的数组顺序为[**4**，**3**，**20**，**43**，**89**，**77**]。

正如你所看到的，主元**43**右边的所有元素都大于**43**，而左边的元素都小于**43**。因此，分区完成。

使用分割点**43**和索引**3**，我们将递归地对两个子数组进行排序，即[**4**，**30**，**20**]和[**89**，**77**]，使用刚刚经历的相同过程。

主`quick_sort`函数的主体如下：

```py
    def quick_sort(unsorted_array, first, last): 
        if last - first <= 0: 
            return 
    else: 
        partition_point = partition(unsorted_array, first, last) 
        quick_sort(unsorted_array, first, partition_point-1) 
        quick_sort(unsorted_array, partition_point+1, last) 
```

`quick_sort`函数是一个非常简单的方法，代码不超过六行。繁重的工作由`partition`函数完成。当调用`partition`方法时，它返回分区点。这是`unsorted_array`数组中的一个点，其中所有左边的元素都小于主元值，而右边的元素都大于它。

当我们在分区进程之后立即打印`unsorted_array`的状态时，我们清楚地看到了分区是如何发生的：

```py
Output:
[43, 3, 20, 89, 4, 77]
[4, 3, 20, 43, 89, 77]
[3, 4, 20, 43, 89, 77]
[3, 4, 20, 43, 77, 89]
[3, 4, 20, 43, 77, 89]
```

退一步，让我们在第一次分区后对第一个子数组进行排序。当`[4, 3, 20]`子数组的分区停止时，`greater_than_pivot_index` 在索引 `2`，`less_than_pivot_index` 在索引 `1`。此时，两个标记被认为已经交叉。因为 `greater_than_pivot_index` 大于 `less_than_pivot_index`，`while` 循环的进一步执行将停止。将主元 `4` 与 `3` 交换，同时索引 `1` 被返回为分区点。

在快速排序算法中，分区算法需要 `O(n)` 时间。由于快速排序算法遵循“分而治之”的范式，它需要 `O(log n)` 时间；因此，快速排序算法的整体平均情况运行时间复杂度为 `O(n) * O(log n) = O(n log n)`。快速排序算法给出了最坏情况的运行时间复杂度为 `O(n²)`。快速排序算法的最坏情况复杂度是每次选择最坏的主元点，并且其中一个分区始终只有一个元素。例如，如果列表已经排序，最坏情况复杂度将发生在分区选择最小元素作为主元点时。当最坏情况复杂度发生时，可以通过使用随机化快速排序来改进快速排序算法。与其他上述排序算法相比，快速排序算法在对大量数据进行排序时非常高效。

# 堆排序算法

在第八章《图和其他算法》中，我们实现了一个二叉堆数据结构。我们的实现始终确保，在从堆中移除或添加元素后，使用 `sink()` 和 `arrange()` 辅助方法来维护堆顺序属性。

堆数据结构可以用来实现一种称为堆排序的排序算法。简而言之，让我们创建一个包含以下项目的简单堆：

```py
    h = Heap() 
    unsorted_list = [4, 8, 7, 2, 9, 10, 5, 1, 3, 6] 
    for i in unsorted_list: 
        h.insert(i) 
    print("Unsorted list: {}".format(unsorted_list)) 
```

堆 `h` 被创建，`unsorted_list` 中的元素被插入。在每次调用 `insert` 方法后，堆顺序属性都会通过随后调用 `float` 方法得到恢复。循环结束后，元素 `4` 将位于我们的堆顶。

我们的堆中的元素数量为 `10`。如果我们在 `h` 堆对象上调用 `pop` 方法 10 次，并存储被弹出的实际元素，我们最终得到一个排序好的列表。每次 `pop` 操作后，堆都会被调整以保持堆顺序属性。

`heap_sort` 方法如下：

```py
    class Heap: 
        ... 
        def heap_sort(self): 
            sorted_list = [] 
            for node in range(self.size): 
                n = self.pop() 
                sorted_list.append(n) 

            return sorted_list 
```

`for` 循环简单地调用 `pop` 方法 `self.size` 次。现在，循环结束后，`sorted_list` 将包含一个排序好的项目列表。

`insert` 方法被调用了 *n* 次。加上 `arrange()` 方法，`insert` 操作的最坏情况运行时间为 `O(n log n)`，`pop` 方法也是如此。因此，这种排序算法的最坏情况运行时间为 `O(n log n)`。

不同排序算法的复杂性比较如下表所示：

| **算法** | **最坏情况** | **平均情况** | **最佳情况** |
| --- | --- | --- | --- |
| 冒泡排序 | `O(n²)` | `O(n²)` | `O(n)` |
| 插入排序 | `O(n²)` | `O(n²)` | `O(n)` |
| 选择排序 | `O(n²)` | `O(n²)` | `O(n²)` |
| 快速排序 | `O(n²)` | `O(n log n)` | `O(n log n)` |
| 堆排序 | `O(n log n)` | `O(n log n)` | `O(n log n)` |

# 总结

在本章中，我们探讨了许多重要和流行的排序算法，这些算法对许多实际应用非常有用。我们讨论了冒泡排序、插入排序、选择排序、快速排序和堆排序算法，以及它们在 Python 中的实现解释。快速排序比其他排序算法表现要好得多。在所有讨论的算法中，快速排序保留了它所排序的列表的索引。在下一章中，我们将利用这一特性来探讨选择算法。

在下一章中，我们将讨论与选择策略和算法相关的概念。


# 第十一章：选择算法

与在无序项目列表中查找元素相关的一组有趣的算法是选择算法。给定一个元素列表，选择算法用于从列表中找到第 i 个最小元素。在这样做的过程中，我们将回答与选择一组数字的中位数和在列表中选择第 i 个最小或最大元素有关的问题。

在本章中，我们将涵盖以下主题：

+   排序选择

+   随机选择

+   确定性选择

# 技术要求

本章中使用的所有源代码都在以下 GitHub 链接中提供：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter11`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter11)。

# 排序选择

列表中的项目可能会接受统计调查，比如找到平均值、中位数和众数。找到平均值和众数并不需要列表被排序。然而，要在数字列表中找到中位数，列表必须首先被排序。找到中位数需要你找到有序列表中间位置的元素。此外，当我们想要找到列表中最后最小的项目或者第一个最小的项目时，可以使用选择算法。

要在无序项目列表中找到第 i 个最小数，获取该项目出现的索引是很重要的。由于列表的元素没有排序，很难知道列表中索引为 0 的元素是否真的是第一个最小数。

处理无序列表时一个实用且明显的做法是首先对列表进行排序。在列表排序后，你可以放心地认为索引为 0 的元素将持有列表中的第一个最小元素。同样，列表中的最后一个元素将持有列表中的最后一个最小元素。然而，在长列表中应用排序算法来获取列表中的最小值或最大值并不是一个好的解决方案，因为排序是一个非常昂贵的操作。

让我们讨论一下是否可能在不排序列表的情况下找到第 i 个最小元素。

# 随机选择

在前一章中，我们讨论了快速排序算法。快速排序算法允许我们对无序项目列表进行排序，但在排序算法运行时保留元素索引的方法。一般来说，快速排序算法执行以下操作：

1.  选择一个主元素

1.  围绕主元素对未排序的列表进行分区

1.  使用*步骤 1*和*步骤 2*递归地对分区列表的两半进行排序

一个有趣且重要的事实是，在每次分区步骤之后，主元素的索引不会改变，即使列表已经排序。这意味着在每次迭代后，所选的主元素值将被放置在列表中的正确位置。正是这个属性使我们能够在一个不太完全排序的列表中获得第 i 个最小数。因为随机选择是基于快速排序算法的，它通常被称为快速选择。

# 快速选择

快速选择算法用于获取无序项目列表中的第 k 个最小元素，并基于快速排序算法。在快速排序中，我们递归地对主元素的两个子列表进行排序。在快速排序中，每次迭代中，我们知道主元素值达到了正确的位置，两个子列表（左子列表和右子列表）的所有元素都被设置为无序。

然而，在快速选择算法中，我们递归地调用函数，专门针对具有第`k`小元素的子列表。在快速选择算法中，我们将枢轴点的索引与`k`值进行比较，以获取给定无序列表中的第`k`小元素。快速选择算法中将会有三种情况，它们如下：

1.  如果枢轴点的索引小于`k`，那么我们可以确定第`k`小的值将出现在枢轴点右侧的子列表中。因此，我们只需递归地调用快速选择函数来处理右子列表。

1.  如果枢轴点的索引大于`k`，那么很明显第`k`小的元素将出现在枢轴点左侧。因此，我们只需递归地在左子列表中寻找第`i`个元素。

1.  如果枢轴点的索引等于`k`，那么意味着我们已经找到了第`k`小的值，并将其返回。

让我们通过一个例子来理解快速选择算法的工作原理。假设有一个元素列表`{45, 23, 87, 12, 72, 4, 54, 32, 52}`，我们想要找出这个列表中第 3 个最小的元素——我们通过使用快速排序算法来实现这一点。

我们通过选择一个枢轴值，即 45，来开始算法。在算法的第一次迭代之后，我们将枢轴值放置在列表中的正确位置，即索引 4（索引从 0 开始）。现在，我们将枢轴值的索引（即 4）与`k`的值（即第 3 个位置，或索引 2）进行比较。由于这是在`k<枢轴`点（即 2<4），我们只考虑左子列表，并递归调用函数。

现在，我们取左子列表并选择枢轴点（即**4**）。运行后，**4**被放置在其正确的位置（即 0 索引）。由于枢轴的索引小于`k`的值，我们考虑右子列表。同样，我们将**23**作为枢轴点，它也被放置在了正确的位置。现在，当我们比较枢轴点的索引和`k`的值时，它们是相等的，这意味着我们已经找到了第 3 个最小的元素，并将其返回。

这个过程也在下面的图表中显示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/15c61235-c781-4d49-aff5-38a00a946718.png)

要实现快速选择算法，我们首先需要了解主要函数，其中有三种可能的情况。我们将算法的主要方法声明如下：

```py
    def quick_select(array_list, left, right, k): 

        split = partition(array_list, left, right) 

        if split == k: 
            return array_list[split] 
        elif split < k: 
            return quick_select(array_list, split + 1, right, k) 
        else: 
            return quick_select(array_list, left, split-1, k) 
```

`quick_select`函数接受列表中第一个元素的索引以及最后一个元素的索引作为参数。第三个参数`k`指定了第`i`个元素。`k`的值应该始终是正数；只有大于或等于零的值才被允许，这样当`k`为 0 时，我们知道要在列表中搜索第一个最小的项。其他人喜欢处理`k`参数，使其直接映射到用户正在搜索的索引，这样第一个最小的数字就映射到排序列表的`0`索引。

对`partition`函数的方法调用`split = partition(array_list, left, right)`，返回`split`索引。`split`数组的这个索引是无序列表中的位置，`right`到`split-1`之间的所有元素都小于`split`数组中包含的元素，而`split+1`到`left`之间的所有元素都大于它。

当`partition`函数返回`split`值时，我们将其与`k`进行比较，以找出`split`是否对应于第`k`个项。

如果`split`小于`k`，那么意味着第`k`小的项应该存在或者被找到在`split+1`和`right`之间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b609a32d-9262-441a-9e70-12d26502cff8.png)

在上述示例中，一个想象中的未排序列表在索引**5**处发生了分割，而我们正在寻找第二小的数字。由于 5<2 得到`false`，因此进行递归调用以返回`quick_select(array_list, left, split-1, k)`，以便搜索列表的另一半。

如果`split`索引小于`k`，那么我们将调用`quick_select`，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/46160450-f11f-4a78-9139-0ceb47a7e1e3.png)

# 理解分区步骤

分区步骤类似于快速排序算法中的步骤。有几点值得注意：

```py
    def partition(unsorted_array, first_index, last_index): 
        if first_index == last_index: 
            return first_index 

        pivot = unsorted_array[first_index] 
        pivot_index = first_index 
        index_of_last_element = last_index 

        less_than_pivot_index = index_of_last_element 
        greater_than_pivot_index = first_index + 1 

        while True: 

            while unsorted_array[greater_than_pivot_index] < pivot and  
                  greater_than_pivot_index < last_index: 
                  greater_than_pivot_index += 1 
            while unsorted_array[less_than_pivot_index] > pivot and 
                  less_than_pivot_index >= first_index: 
                  less_than_pivot_index -= 1 

            if greater_than_pivot_index < less_than_pivot_index: 
                temp = unsorted_array[greater_than_pivot_index] 
                unsorted_array[greater_than_pivot_index] = 
                    unsorted_array[less_than_pivot_index] 
                unsorted_array[less_than_pivot_index] = temp 
            else: 
                break 

        unsorted_array[pivot_index] =  
            unsorted_array[less_than_pivot_index] 
        unsorted_array[less_than_pivot_index] = pivot 

        return less_than_pivot_index 
```

在函数定义的开头插入了一个`if`语句，以应对`first_index`等于`last_index`的情况。在这种情况下，这意味着我们的子列表中只有一个元素。因此，我们只需返回函数参数中的任何一个，即`first_index`。

第一个元素总是选择为枢轴。这种选择使第一个元素成为枢轴是一个随机决定。通常不会产生良好的分割，随后也不会产生良好的分区。然而，最终将找到第`i^(th)`个元素，即使枢轴是随机选择的。

`partition`函数返回由`less_than_pivot_index`指向的枢轴索引，正如我们在前一章中看到的。

# 确定性选择

随机选择算法的最坏情况性能是`O(n²)`。可以通过改进随机选择算法的元素部分来获得`O(n)`的最坏情况性能。我们可以通过使用一个算法，即**确定性选择**，获得`O(n)`的性能。

中位数中位数是一种算法，它为我们提供了近似中位数值，即接近给定未排序元素列表的实际中位数的值。这个近似中位数通常用作快速选择算法中选择列表中第`i^(th)`最小元素的枢轴点。这是因为中位数中位数算法在线性时间内找到了估计中位数，当这个估计中位数用作快速选择算法中的枢轴点时，最坏情况下的运行时间复杂度从`O(n²)`大幅提高到线性的`O(n)`。因此，中位数中位数算法帮助快速选择算法表现得更好，因为选择了一个好的枢轴值。

确定性算法选择第`i^(th)`最小元素的一般方法如下：

1.  选择一个枢轴：

1.  将未排序项目的列表分成每组五个元素。

1.  对所有组进行排序并找到中位数。

1.  递归执行*步骤 1*和*2*，以获得列表的真实中位数。

1.  使用真实中位数来分区未排序项目的列表。

1.  递归到可能包含第`i^(th)`最小元素的分区列表部分。

让我们考虑一个包含 15 个元素的示例列表，以了解确定性方法确定列表中第三个最小元素的工作原理。首先，您需要将具有 5 个元素的列表分成两个，并对子列表进行排序。一旦我们对列表进行了排序，我们就找出子列表的中位数，也就是说，元素**23**、**52**和**34**是这三个子列表的中位数。我们准备了所有子列表中位数的列表，然后对中位数列表进行排序。接下来，我们确定这个列表的中位数，也就是中位数的中位数，即**34**。这个值是整个列表的估计中位数，并用于选择整个列表的分区/枢轴点。由于枢轴值的索引为 7，大于`i^(th)`值，我们递归考虑左子列表。

算法的功能如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b894d148-b32e-4111-88f6-9d397cbc815b.png)

# 枢轴选择

为了有效地确定列表中第 i 个最小值的确定性算法，我们首先要实现枢轴选择方法。在随机选择算法中，我们以前选择第一个元素作为枢轴。我们将用一系列步骤替换该步骤，使我们能够获得近似中位数。这将改善关于枢轴的列表的分区：

```py
    def partition(unsorted_array, first_index, last_index): 

        if first_index == last_index: 
            return first_index 
        else: 
            nearest_median =     
            median_of_medians(unsorted_array[first_index:last_index]) 

        index_of_nearest_median = 
            get_index_of_nearest_median(unsorted_array, first_index, 
                                        last_index, nearest_median) 

        swap(unsorted_array, first_index, index_of_nearest_median) 

        pivot = unsorted_array[first_index] 
        pivot_index = first_index 
        index_of_last_element = last_index 

        less_than_pivot_index = index_of_last_element 
        greater_than_pivot_index = first_index + 1 
```

现在让我们了解 partition 函数的代码。nearest_median 变量存储给定列表的真实或近似中位数：

```py
    def partition(unsorted_array, first_index, last_index): 

        if first_index == last_index: 
            return first_index 
        else: 
            nearest_median =   
            median_of_medians(unsorted_array[first_index:last_index]) 
        .... 
```

如果 unsorted_array 参数只有一个元素，first_index 和 last_index 将相等。因此，first_index 会被返回。

然而，如果列表的大小大于 1，我们将使用由 first_index 和 last_index 标记的数组部分调用 median_of_medians 函数。返回值再次存储在 nearest_median 中。

# 中位数中位数

median_of_medians 函数负责找到任何给定项目列表的近似中位数。该函数使用递归返回真正的中位数：

```py
def median_of_medians(elems): 

    sublists = [elems[j:j+5] for j in range(0, len(elems), 5)] 

    medians = [] 
    for sublist in sublists: 
        medians.append(sorted(sublist)[len(sublist)//2]) 

    if len(medians) <= 5: 
        return sorted(medians)[len(medians)//2] 
    else: 
        return median_of_medians(medians) 
```

该函数首先将列表 elems 分成每组五个元素。这意味着如果 elems 包含 100 个项目，将会有 20 个组，由 sublists = [elems[j:j+5] for j in range(0, len(elems), 5)]语句创建，每个组包含恰好五个元素或更少：

```py
    medians = [] 
        for sublist in sublists: 
            medians.append(sorted(sublist)[len(sublist)/2]) 
```

创建一个空数组并将其分配给 medians，它存储分配给 sublists 的每个五个元素数组中的中位数。

for 循环遍历 sublists 中的列表列表。每个子列表都被排序，找到中位数，并存储在 medians 列表中。

medians.append(sorted(sublist)[len(sublist)//2])语句将对列表进行排序并获得存储在其中间索引的元素。这成为五个元素列表的中位数。由于列表的大小很小，使用现有的排序函数不会影响算法的性能。

从一开始我们就明白，我们不会对列表进行排序以找到第 i 个最小的元素，那么为什么要使用 Python 的 sorted 方法呢？嗯，因为我们要对一个非常小的列表进行排序，只有五个元素或更少，所以这个操作对算法的整体性能的影响被认为是可以忽略的。

此后，如果列表现在包含五个或更少的元素，我们将对 medians 列表进行排序，并返回位于其中间索引的元素：

```py
    if len(medians) <= 5: 
            return sorted(medians)[len(medians)/2] 
```

另一方面，如果列表的大小大于五，我们将再次递归调用 median_of_medians 函数，向其提供存储在 medians 中的中位数列表。

例如，为了更好地理解中位数中位数算法的概念，我们可以看下面的数字列表：

*[2, 3, 5, 4, 1, 12, 11, 13, 16, 7, 8, 6, 10, 9, 17, 15, 19, 20, 18, 23, 21, 22, 25, 24, 14]*

我们可以将这个列表分成每组五个元素，使用代码语句 sublists = [elems[j:j+5] for j in range(0, len(elems), 5]来获得以下列表：

*[[2, 3, 5, 4, 1], [12, 11, 13, 16, 7], [8, 6, 10, 9, 17], [15, 19, 20, 18, 23], [21, 22, 25, 24, 14]]*

对每个五个元素的列表进行排序并获得它们的中位数，得到以下列表：

*[3, 12, 9, 19, 22]*

由于列表有五个元素，我们只返回排序后列表的中位数；否则，我们将再次调用 median_of_median 函数。

中位数中位数算法也可以用于选择快速排序算法中的枢轴点，从而将快速排序算法的最坏情况性能从 O(n²)显著提高到 O(n log n)的复杂度。

# 分区步骤

现在我们已经获得了近似中位数，get_index_of_nearest_median 函数使用 first 和 last 参数指示的列表边界：

```py
    def get_index_of_nearest_median(array_list, first, second, median): 
        if first == second: 
            return first 
        else: 
            return first + array_list[first:second].index(median) 
```

再次，如果列表中只有一个元素，我们只返回第一个索引。但是，`arraylist[first:second]`返回一个索引从`0`到`list-1`大小的数组。当我们找到中位数的索引时，由于`[first:second]`代码返回的新范围索引，我们失去了它所在的列表部分。因此，我们必须将`arraylist[first:second]`返回的任何索引添加到`first`以获得中位数的真实索引位置：

```py
    swap(unsorted_array, first_index, index_of_nearest_median) 
```

然后使用`swap`函数将`unsorted_array`中的第一个元素与`index_of_nearest_median`进行交换。

交换两个数组元素的`utility`函数如下所示：

```py
def swap(array_list, first, second): 
    temp = array_list[first] 
    array_list[first] = array_list[second] 
    array_list[second] = temp 
```

我们的近似中位数现在存储在未排序列表的`first_index`处。

分区函数继续进行，就像在快速选择算法的代码中一样。分区步骤之后，数组看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ae12fc42-27b4-4a09-b4ad-561e164c2163.png)

```py

 def deterministic_select(array_list, left, right, k): 

        split = partition(array_list, left, right) 
        if split == k: 
            return array_list[split] 
        elif split < k : 
           return deterministic_select(array_list, split + 1, right, k) 
        else: 
            return deterministic_select(array_list, left, split-1, k)
```

正如您已经观察到的那样，确定性选择算法的主要函数看起来与其随机选择对应函数完全相同。在对初始的`array_list`进行分区以获得近似中位数之后，会与第`k`个元素进行比较。

如果`split`小于`k`，那么会对`deterministic_select(array_list, split + 1, right, k)`进行递归调用。这将在数组的一半中寻找第`k`个元素。否则，会调用`deterministic_select(array_list, left, split-1, k)`函数。

# 总结

在本章中，我们讨论了回答如何在列表中找到第`i`个最小元素的各种方法。探讨了简单地对列表进行排序以执行找到第`i`个最小元素操作的平凡解决方案。

还有可能不一定在确定第`i`个最小元素之前对列表进行排序。随机选择算法允许我们修改快速排序算法以确定第`i`个最小元素。

为了进一步改进随机选择算法，以便获得`O(n)`的时间复杂度，我们着手寻找中位数中的中位数，以便在分区过程中找到一个良好的分割点。

在下一章中，我们将探讨字符串的世界。我们将学习如何高效地存储和操作大量文本。还将涵盖数据结构和常见的字符串操作。
