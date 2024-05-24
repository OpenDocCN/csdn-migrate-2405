# Python 入门指南（三）

> 原文：[`zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92`](https://zh.annas-archive.org/md5/97bc15629f1b51a0671040c56db61b92)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：算法设计原则

我们为什么要学习算法设计？当然有很多原因，我们学习某事的动机很大程度上取决于我们自己的情况。对于对算法设计感兴趣有重要的职业原因。算法是所有计算的基础。我们认为计算机是硬件，硬盘、内存芯片、处理器等等。然而，如果缺少的是算法，现代技术将不可能存在。

算法的理论基础是图灵机，几十年前就建立了这种机器的数学模型，而数字逻辑电路实际上能够实现这样的机器。图灵机本质上是一个数学模型，它使用预定义的一组规则，将一组输入转换为一组输出。图灵机的第一批实现是机械的，下一代可能会看到数字逻辑电路被量子电路或类似的东西所取代。无论平台如何，算法都起着中心主导的作用。

算法的另一个方面是它对技术创新的影响。显而易见的例子是页面排名搜索算法，谷歌搜索引擎就是基于它的变体。使用这种算法和类似的算法允许研究人员、科学家、技术人员和其他人能够快速地搜索大量信息。这对新研究的速度、新发现的速度以及新的创新技术的发展速度都有巨大影响。

算法的研究也很重要，因为它训练我们对某些问题进行非常具体的思考。它可以通过帮助我们分离问题的组成部分并定义这些组成部分之间的关系，来增强我们的思维和问题解决能力。总之，学习算法有四个主要原因：

1.  它们对计算机科学和*智能*系统至关重要。

1.  它们在许多其他领域（计算生物学、经济学、生态学、通信、生态学、物理学等）中都很重要。

1.  它们在技术创新中发挥作用。

1.  它们改善问题解决和分析思维能力。

算法在最简单的形式中只是一系列操作，一系列指令。它可能只是一个线性结构，形式为做*x*，然后做*y*，然后做*z*，然后完成。然而，为了使事情更有用，我们添加了诸如在 Python 中的`if-else`语句的子句。在这里，未来的行动取决于某些条件；比如数据结构的状态。我们还添加了操作、迭代，while 和 for 语句。进一步扩展我们的算法素养，我们添加了递归。递归通常可以实现与迭代相同的结果，但它们在根本上是不同的。递归函数调用自身，将相同的函数应用于逐渐减小的输入。任何递归步骤的输入都是前一个递归步骤的输出。

基本上，我们可以说算法由以下四个元素组成：

+   顺序操作

+   基于数据结构状态的操作

+   迭代，重复执行一定次数的操作

+   递归，在一组输入上调用自身

# 算法设计范式

总的来说，我们可以分辨出三种广泛的算法设计方法。它们是：

+   分而治之

+   贪婪算法

+   动态规划

顾名思义，分而治之范式涉及将问题分解为较小的子问题，然后以某种方式将结果组合起来以获得全局解。这是一种非常常见和自然的问题解决技术，可以说是最常用的算法设计方法。

贪婪算法通常涉及优化和组合问题；经典的例子是将其应用于旅行推销员问题，贪婪方法总是首先选择最近的目的地。这种最短路径策略涉及在希望这将导致全局解决方案的情况下找到局部问题的最佳解决方案。

动态规划方法在我们的子问题重叠时非常有用。这与分治不同。与将问题分解为独立的子问题不同，动态规划中间结果被缓存并可以在后续操作中使用。与分治一样，它使用递归；然而，动态规划允许我们在不同阶段比较结果。对于某些问题，这可能比分治具有性能优势，因为通常更快地从内存中检索先前计算的结果，而不必重新计算它。

# 递归和回溯

递归特别适用于分治问题；然而，要准确理解发生了什么可能有些困难，因为每次递归调用都会产生其他递归调用。递归函数的核心是两种类型的情况：基本情况，告诉递归何时终止，和递归情况，调用它们所在的函数。一个自然适合递归解决方案的简单问题是计算阶乘。递归阶乘算法定义了两种情况：当*n*为零时的基本情况，和当*n*大于零时的递归情况。一个典型的实现如下：

```py
    def factorial(n):
        #test for a base case
        if n==0:
            return 1
            # make a calculation and a recursive call
            f= n*factorial(n-1)
        print(f)
        return(f)
        factorial(4)
```

这段代码打印出数字 1、2、4、24\. 要计算 4 需要进行四次递归调用加上初始的父调用。在每次递归中，方法的变量副本都存储在内存中。一旦方法返回，它就会从内存中移除。以下是我们可以将这个过程可视化的一种方式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ceaff8fe-caa4-42cf-8dd5-f0e739a5d7fa.png)

可能并不清楚递归还是迭代对于特定问题更好的解决方案；毕竟它们都重复一系列操作，并且都非常适合分治算法设计。迭代一直运行直到问题完成。递归将问题分解为越来越小的块，然后将结果组合起来。迭代对程序员来说通常更容易，因为控制保持在循环内部，而递归可以更接近数学概念，比如阶乘。递归调用存储在内存中，而迭代不会。这在处理器周期和内存使用之间产生了一种权衡，因此选择使用哪种可能取决于任务是处理器密集型还是内存密集型。以下表格概述了递归和迭代之间的主要区别：

| **递归** | **迭代** |
| --- | --- |
| 当达到基本情况时终止 | 当满足定义的条件时终止 |
| 每次递归调用都需要内存空间 | 每次迭代都不会存储在内存中 |
| 无限递归会导致堆栈溢出错误 | 无限迭代将在硬件通电时运行 |
| 有些问题自然更适合递归解决方案 | 迭代解决方案可能并不总是显而易见 |

# 回溯

回溯是一种特别适用于遍历树结构等问题类型的递归形式，在每个节点我们都有多个选项可供选择。随后我们会面临不同的选项，并根据所做的选择系列达到目标状态或死胡同。如果是后者，我们必须回溯到上一个节点并遍历不同的分支。回溯是一种穷举搜索的分治方法。重要的是，回溯会剪枝不能给出结果的分支。

在下面的示例中给出了回溯的一个例子。在这里，我们使用了递归方法来生成给定长度*n*的给定字符串*s*的所有可能的排列：

```py
    def bitStr(n, s):            

         if n == 1: return s 
         return [ digit + bits for digit in bitStr(1,s)for bits in bitStr(n - 1,s)] 

    print (bitStr(3,'abc'))     
```

这产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/b1ab5929-7ac9-4dec-b033-e9fde81b5b2b.png)

注意这个双列表压缩和这个理解中的两个递归调用。这个递归地连接了初始序列的每个元素，当`*n* = 1`时返回，与前一个递归调用中生成的字符串的每个元素。在这个意义上，它是*回溯*，以揭示先前未生成的组合。返回的最终字符串是初始字符串的所有*n*个字母组合。

# 分而治之 - 长乘法

为了使递归不仅仅是一个聪明的技巧，我们需要了解如何将其与其他方法进行比较，比如迭代，以及了解何时使用它将导致更快的算法。我们都熟悉的迭代算法是我们在小学数学课上学到的程序，用于相乘两个大数。也就是说，长乘法。如果你记得的话，长乘法涉及迭代相乘和进位操作，然后是移位和加法操作。

我们的目标是在这里检查如何测量这个过程的效率，并尝试回答这个问题：这是我们用来相乘两个大数的最有效的程序吗？

在下图中，我们可以看到将两个 4 位数相乘需要 16 次乘法运算，我们可以推广说，一个*n*位数需要大约*n²*次乘法运算：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/a349984a-9f69-4c49-b418-7ff885bc6a42.png)

以计算原语的数量，如乘法和加法，来分析算法的方法很重要，因为它为我们提供了一种理解完成某个计算所需的时间与该计算的输入大小之间的关系的方法。特别是，我们想知道当输入，即数字的位数*n*非常大时会发生什么。这个主题，称为渐近分析，或时间复杂度，对我们研究算法至关重要，我们将在本章和本书的其余部分经常回顾它。

# 我们能做得更好吗？递归方法

事实证明，在长乘法的情况下，答案是肯定的，实际上有几种算法可以用于乘法大数，需要更少的操作。最著名的长乘法替代方案之一是**Karatsuba 算法**，首次发表于 1962 年。这采用了一种基本不同的方法：而不是迭代地相乘单个数字，它以递归的方式对逐渐变小的输入进行乘法运算。递归程序在输入的较小子集上调用自己。构建递归算法的第一步是将一个大数分解为几个较小的数。这样做的最自然的方式是将数字简单地分成两半，前半部分是最重要的数字，后半部分是最不重要的数字。例如，我们的四位数 2345 变成了一对两位数 23 和 45。我们可以使用以下更一般的分解来分解任何 2 *n*位数*x*和*y*，其中*m*是小于*n*的任何正整数：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0ca172df-86c2-4780-bf6a-9570e18aab94.png)![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/55df9f14-ece8-4cbb-ae31-8b23c3267211.png)

现在我们可以将我们的乘法问题*x*，*y*重写如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/35b80ce5-cbcc-4638-8799-346532ee2154.png)

当我们展开并收集同类项时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/d5f89699-bf11-480c-9db2-0deae29ac8eb.png)

更方便的是，我们可以这样写：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ad955c99-182e-4f77-a7d2-df5800b6215f.jpg)

其中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/7bb07889-0803-436c-84b5-8edb5a6eb21d.jpg)

应该指出，这表明了一种递归方法来计算两个数字的乘法，因为这个过程本身涉及乘法。具体来说，乘积*ac*、*ad*、*bc*和*bd*都涉及比输入数字小的数字，因此我们可以将相同的操作作为整体问题的部分解决方案。到目前为止，这个算法包括四个递归乘法步骤，目前还不清楚它是否比经典的长乘法方法更快。

到目前为止，关于递归乘法的讨论对数学家来说自 19 世纪末就已经很熟悉了。卡拉茨巴算法改进了这一点，方法是做出以下观察。我们实际上只需要知道三个量：*z[2]*= *ac*；*z[1]=ad +bc*，和*z[0]*= *bd* 来解方程 3.1。我们只需要知道*a, b, c, d*的值，因为它们对计算*z[2]*, *z[1]*, 和*z[0]*所涉及的总和和乘积有贡献。这表明也许我们可以减少递归步骤的数量。事实证明的确是这种情况。

由于乘积*ac*和*bd*已经处于最简形式，似乎我们不太可能消除这些计算。然而，我们可以做出以下观察：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/319a0a26-74e5-4319-9eff-7b0e7dea8bef.jpg)

当我们减去我们在上一个递归步骤中计算的*ac*和*bd*时，我们得到我们需要的数量，即(*ad* + *bc*)：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/03bddaec-240b-473a-a996-0718fc542efd.jpg)

这表明我们确实可以计算*ad + bc*的和，而无需单独计算每个单独的数量。总之，我们可以通过将递归步骤从四步减少到三步来改进方程 3.1。这三个步骤如下：

1.  递归计算*ac*。

1.  递归计算*bd*。

1.  递归计算(*a* +*b*)(*c* + *d*)并减去*ac*和*bd*。

以下示例展示了卡拉茨巴算法的 Python 实现：

```py
    from math import log10  
    def karatsuba(x,y): 

        # The base case for recursion 
        if x < 10 or y < 10: 
            return x*y     

        #sets n, the number of digits in the highest input number 
        n = max(int(log10(x)+1), int(log10(y)+1)) 

        # rounds up n/2     
        n_2 = int(math.ceil(n / 2.0)) 
        #adds 1 if n is uneven 
        n = n if n % 2 == 0 else n + 1 

        #splits the input numbers      
        a, b = divmod(x, 10**n_2) 
        c, d = divmod(y, 10**n_2) 

        #applies the three recursive steps 
        ac = karatsuba(a,c) 
        bd = karatsuba(b,d) 
        ad_bc = karatsuba((a+b),(c+d)) - ac - bd 

        #performs the multiplication     
        return (((10**n)*ac) + bd + ((10**n_2)*(ad_bc))) 
```

为了确保这确实有效，我们可以运行以下测试函数：

```py
    import random 
    def test(): 
            for i in range(1000): 
                x = random.randint(1,10**5) 
                y = random.randint(1,10**5) 
                expected = x * y 
                result = karatsuba(x, y) 
                if result != expected: 
                    return("failed")                 
            return('ok')   
```

# 运行时间分析

很明显，算法设计的一个重要方面是评估效率，无论是在空间（内存）还是时间（操作次数）方面。第二个度量，称为运行性能，是本节的主题。值得一提的是，用于衡量算法内存性能的度量标准与此相同。我们可以以多种方式衡量运行时间，最明显的可能是简单地测量算法完成所需的时间。这种方法的主要问题在于算法运行所需的时间很大程度上取决于其运行的硬件。衡量算法运行时间的一个与平台无关的方法是计算所涉及的操作次数。然而，这也存在问题，因为没有明确的方法来量化一个操作。这取决于编程语言、编码风格以及我们决定如何计算操作。然而，如果我们将这种计算操作的想法与一个期望相结合，即随着输入规模的增加，运行时间将以特定方式增加，那么我们就可以使用这个想法。也就是说，输入规模*n*与算法运行时间之间存在数学关系。

接下来的讨论大部分将围绕以下三个指导原则展开。随着我们的进行，这些原则的合理性和重要性将变得更加清晰。这些原则如下：

+   最坏情况分析。不对输入数据做任何假设。

+   忽略或抑制常数因子和低阶项。在大输入中，高阶项占主导地位。

+   关注输入规模较大的问题。

最坏情况分析是有用的，因为它给出了我们算法保证不会超过的严格上界。忽略小的常数因子和低阶项实际上就是忽略那些在输入大小*n*的大值时并不对总运行时间有很大贡献的事物。这不仅使我们的工作在数学上更容易，也使我们能够专注于对性能影响最大的事物。

我们在 Karatsuba 算法中看到，乘法操作的数量增加到了输入大小*n*的平方。如果我们有一个四位数，乘法操作的数量是 16；一个八位数需要 64 次操作。通常，我们并不真正关心算法在*n*的小值上的行为，所以我们通常忽略那些随着*n*线性增长的因素。这是因为在较大的*n*值上，随着*n*的增加，增长最快的操作将占主导地位。

我们将通过一个例子，归并排序算法，更详细地解释这一点。排序是第十三章的主题，*排序*，然而，作为一个前导和了解运行时性能的有用方式，我们将在这里介绍归并排序。

归并排序算法是一个经典的算法，已经发展了 60 多年。它仍然广泛应用于许多最流行的排序库中。它相对简单而高效。它是一个使用分治法的递归算法。这涉及将问题分解为更小的子问题，递归地解决它们，然后以某种方式将结果合并。归并排序是分治范式的最明显的演示之一。

归并排序算法由三个简单的步骤组成：

1.  递归地对输入数组的左半部分进行排序。

1.  递归地对输入数组的右半部分进行排序。

1.  将两个排序好的子数组合并成一个。

一个典型的问题是将一组数字按数字顺序排序。归并排序通过将输入分成两半并同时处理每一半来工作。我们可以用以下图表来形象地说明这个过程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/250a5ae4-7c53-4800-9d19-06c6c7f8dc5c.png)

以下是归并排序算法的 Python 代码：

```py
    def mergeSort(A): 
        #base case if the input array is one or zero just return. 
        if len(A) > 1: 
            # splitting input array 
            print('splitting ', A ) 
            mid = len(A)//2 
            left = A[:mid] 
            right = A[mid:] 
            #recursive calls to mergeSort for left and right sub arrays                 
            mergeSort(left) 
            mergeSort(right) 
            #initalizes pointers for left (i) right (j) and output array (k)  
    # 3 initalization operations 
            i = j = k = 0         
            #Traverse and merges the sorted arrays 
            while i <len(left) and j<len(right): 
    # if left < right comparison operation  
                if left[i] < right[j]: 
    # if left < right Assignment operation 
                    A[k]=left[i] 
                    i=i+1 
                else: 
    #if right <= left assignment 
                    A[k]= right[j] 
                    j=j+1 
                k=k+1 

            while i<len(left): 
    #Assignment operation 
                A[k]=left[i] 
                i=i+1 
                k=k+1 

            while j<len(right): 
    #Assignment operation 
                A[k]=right[j] 
                j=j+1 
                k=k+1 
        print('merging ', A) 
        return(A)   
```

我们运行这个程序得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/038ce698-89ab-4d99-82b2-ac75765f7e84.png)

我们感兴趣的问题是如何确定运行时间性能，也就是说，算法完成所需的时间与*n*的大小相关的增长率是多少。为了更好地理解这一点，我们可以将每个递归调用映射到一个树结构上。

树中的每个节点都是一个递归调用，处理逐渐变小的子问题：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/bdb1209e-db62-4741-8468-d4809f3d0f48.png)

每次调用归并排序都会随后创建两个递归调用，因此我们可以用二叉树表示这一点。每个子节点都接收输入的一个子集。最终，我们想知道算法完成所需的总时间与*n*的大小相关。首先，我们可以计算树的每一层的工作量和操作数量。

关注运行时分析，在第 1 层，问题被分成两个*n*/2 的子问题，在第 2 层，有四个*n*/4 的子问题，依此类推。问题是递归何时结束，也就是说，何时达到基本情况。这只是当数组要么是零要么是一时。

递归级别的数量正好是你需要将*n*除以 2 的次数，直到得到最多为 1 的数字。这恰好是 log2 的定义。由于我们将初始递归调用计为级别 0，总级别数是 log[2]*n* + 1。

让我们暂停一下，重新定义一下。到目前为止，我们一直用字母*n*来描述输入中的元素数量。这指的是递归的第一级中元素的数量，也就是初始输入的长度。我们需要区分后续递归级别的输入大小。为此，我们将使用字母*m*或者特定的*m[j]*来表示递归级别*j*的输入长度。

还有一些细节我们忽略了，我相信你也开始好奇了。例如，当*m*/2 不是整数时会发生什么，或者当我们的输入数组中有重复元素时会发生什么。事实证明，这对我们的分析没有重要影响。

使用递归树来分析算法的优势在于我们可以计算每个递归级别的工作量。定义这个工作量就是操作的总数，这当然与输入的大小有关。以平台无关的方式来衡量和比较算法的性能是很重要的。实际运行时间当然取决于运行的硬件。计算操作次数很重要，因为它给了我们一个与算法性能直接相关的度量标准，与平台无关。

一般来说，由于归并排序的每次调用都会进行两次递归调用，调用次数在每个级别都会翻倍。同时，每次调用都会处理其父级别大小一半的输入。我们可以形式化地表达为：

对于级别*j*，其中*j*是整数 0、1、2... log[2]*n*，每个大小为*n*/2^j 的子问题有 2^j 个。

为了计算总操作次数，我们需要知道单个合并两个子数组所包含的操作次数。让我们来数一下之前 Python 代码中的操作次数。我们感兴趣的是在进行两次递归调用后的所有代码。首先，我们有三个赋值操作。然后是三个 while 循环。在第一个循环中，我们有一个 if else 语句，每个 if else 语句中有两个操作，一个比较，一个赋值。由于在 if else 语句中只有一个这样的操作集，我们可以将这段代码计为每次递归执行 2 次。接下来是两个 while 循环，每个有一个赋值操作。这使得每次归并排序递归的总操作次数为 4*m* + 3。

由于*m*至少为 1，操作次数的上限为 7*m*。必须指出，这并不是一个精确的数字。当然，我们可以决定以不同的方式计算操作次数。我们没有计算增量操作或任何维护操作；然而，在*n*的高值时，我们更关心运行时间的增长速度。

这可能看起来有点令人生畏，因为每次递归调用本身都会产生更多的递归调用，似乎呈指数级增长。使这个问题可控的关键事实是，随着递归调用次数翻倍，每个子问题的大小减半。这两股相反的力量会很好地抵消，我们可以证明这一点。

为了计算递归树每个级别的最大操作次数，我们只需将子问题的数量乘以每个子问题中的操作次数，如下所示：

（图片）

重要的是，这表明，因为 2^j 取消了每个级别上的操作数，所以每个级别上的操作数与级别无关。这给我们每个级别上执行的操作数的上限，例如，在这个例子中，是 7*n*。应该指出，这包括该级别上每个递归调用执行的操作数，而不是在后续级别上进行的递归调用。这表明，随着每个级别的递归调用数量翻倍，所做的工作正好被每个子问题的输入大小减半所抵消。

要找到完整归并排序的总操作数，我们只需将每个级别上的操作数乘以级别数。这给我们以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ac440c24-f7c5-48a7-a083-75d67cff8b8f.jpg)

当我们展开这个式子时，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/d4c151e6-ea4e-4fb6-804c-648353a68837.jpg)

从中要得出的关键点是，输入大小和总运行时间之间存在对数关系。如果您还记得学校数学，对数函数的显著特征是它非常快地变平。作为输入变量，*x*增大，输出变量*y*增加的幅度越来越小。例如，将对数函数与线性函数进行比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/983df66e-1889-4df2-98ba-d00d8853a7c0.png)

在前面的例子中，将*n*log[2]*n*组件与*n*²进行比较。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0c0197f3-2cd7-4b71-91f8-c4bb4a4f5f8c.png)

请注意，对于非常小的*n*值，完成时间*t*实际上比运行时间为 n²的算法更短。然而，对于大约 40 以上的值，对数函数开始占主导地位，使输出变平，直到在相对适中的大小*n*=100 时，性能比运行时间为 n²的算法高出两倍以上。还要注意，在高*n*值时，常数因子+7 的消失是无关紧要的。

生成这些图表所使用的代码如下：

```py
    import matplotlib.pyplot as plt 
    import math 
    x=list(range(1,100)) 
    l =[]; l2=[]; a = 1 
    plt.plot(x , [y * y for y in x] ) 
    plt.plot(x, [(7 *y )* math.log(y, 2) for y in x]) 
    plt.show() 
```

如果尚未安装 matplotlib 库，您需要安装它才能运行。有关详细信息，请访问以下地址；我鼓励您尝试使用列表推导式表达式来生成图表。例如，添加以下绘图语句：

```py
    plt.plot(x, [(6 *y )* math.log(y, 2) for y in x]) 
```

得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/4129159f-5b74-4138-94d0-02abb037cc78.png)

前面的图表显示了计算六次操作或七次操作之间的差异。我们可以看到这两种情况是如何分歧的，这在谈论应用程序的具体情况时很重要。然而，我们在这里更感兴趣的是一种表征增长率的方法。我们更关心的不是绝对值，而是这些值随着*n*的增加而变化的方式。通过这种方式，我们可以看到这两条较低的曲线具有相似的增长率，与顶部（*x*²）曲线相比。我们说这两条较低的曲线具有相同的**复杂度类**。这是一种理解和描述不同运行时行为的方法。我们将在下一节正式化这个性能指标。

# 渐近分析

基本上有三个特征来表征算法的运行时间性能。它们是：

+   最坏情况 - 使用能够获得最慢性能的输入

+   最佳情况 - 使用能够给出最佳结果的输入

+   平均情况 - 假设输入是随机的

为了计算这些，我们需要知道上限和下限。我们已经看到了用数学表达式来表示算法的运行时间的方法，基本上是加法和乘法运算。要使用渐近分析，我们只需创建两个表达式，一个用于最佳情况，一个用于最坏情况。

# 大 O 符号

大 O 符号中的字母“O”代表顺序，以承认增长速度被定义为函数的顺序。我们说一个函数*T*(*n*)是另一个函数*F*(*n*)的大 O，我们将其定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/4b0a93a3-4b55-4fd3-8226-64d255fca9cc.jpg)

输入大小*n*的函数*g*(*n*)基于这样的观察：对于所有足够大的*n*值，*g*(*n*)都受到*F*(*n*)的常数倍的上界限制。目标是找到小于或等于*F*(*n*)的增长速度。我们只关心*n*的较高值发生了什么。变量*n[0]*表示增长速度不重要的阈值。函数 T(n)表示**紧密上界**F(n)。在下图中，我们看到*T*(*n*) = *n²* + 500 = *O*(*n²*)，其中*C* = 2，*n[0]*约为 23：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/6ba4595b-ba4b-4157-9a3f-632eaa3e382a.png)

您还会看到符号*f*(*n*) = *O*(*g*(*n*)）。这描述了*O*(*g*(*n*)）实际上是一个包含所有增长速度与*f*(*n*)相同或更小的函数的集合。例如，*O*(*n²*)也包括函数*O*(*n*)，*O*(*n*log*n*），等等。

在下表中，我们按从最低到最高的顺序列出了最常见的增长率。我们有时称这些增长率为函数的**时间复杂度**，或者函数的复杂度类：

| **复杂度类** | **名称** | **示例操作** |
| --- | --- | --- |
| O(1) | 常数 | 追加，获取项目，设置项目。 |
| O(log*n*) | 对数 | 在排序数组中查找元素。 |
| O(n) | 线性 | 复制，插入，删除，迭代。 |
| *n*Log*n* | 线性对数 | 对列表进行排序，合并 - 排序。 |
| *n²* | 二次 | 在图中找到两个节点之间的最短路径。嵌套循环。 |
| *n³* | 立方 | 矩阵乘法。 |
| 2*^n* | 指数 | '汉诺塔'问题，回溯。 |

# 组合复杂度类

通常，我们需要找到一系列基本操作的总运行时间。事实证明，我们可以将简单操作的复杂度类组合起来，以找到更复杂的组合操作的复杂度类。目标是分析函数或方法中的组合语句，以了解执行多个操作的总时间复杂度。组合两个复杂度类的最简单方法是将它们相加。这发生在我们有两个连续的操作时。例如，考虑将元素插入列表，然后对该列表进行排序的两个操作。我们可以看到插入一个项目需要 O(*n*)时间，排序需要 O(*n*log*n*)时间。我们可以将总时间复杂度写为 O(*n* + *n*log*n*)，也就是说，我们将两个函数放在 O(...)中。我们只关心最高阶项，因此这让我们只剩下 O(*n*log*n*)。

如果我们重复一个操作，例如在 while 循环中，那么我们将复杂度类乘以操作执行的次数。如果一个时间复杂度为 O(*f*(*n*))的操作重复执行 O(*n*)次，那么我们将这两个复杂度相乘：

O(*f*(*n*) * O(*n*)) = O(*nf*(*n*)）。

例如，假设函数 f(...)的时间复杂度为 O(*n*²)，并且在 while 循环中执行*n*次，如下所示：

```py
    for i n range(n): 
        f(...) 
```

然后，这个循环的时间复杂度变成了 O(*n*²) * O(*n*) = O(*n * n²*) = O(*n³*）。在这里，我们只是将操作的时间复杂度乘以这个操作执行的次数。循环的运行时间最多是循环内语句的运行时间乘以迭代次数。一个单独的嵌套循环，也就是一个循环嵌套在另一个循环中，假设两个循环都运行*n*次，那么运行时间就是*n*²。例如：

```py
    for i in range(0,n):  
        for j in range(0,n) 
            #statements 
```

每个语句是一个常数 c，执行*n**n*次，因此我们可以将运行时间表示为；*c**n* *n* = *cn*² = O(*n*2）。

对于嵌套循环中的连续语句，我们将每个语句的时间复杂度相加，并乘以语句执行的次数。例如：

```py
    n = 500    #c0   
    #executes n times 
    for i in range(0,n): 
        print(i)    #c1 
    #executes n times 
    for i in range(0,n): 
        #executes n times 
        for j in range(0,n): 
        print(j)   #c2 
```

这可以写成*c*[0] +*c*[1]*n* + *cn*² = O(*n*²)。

我们可以定义（以 2 为底）对数复杂度，将问题的大小减少一半，所需的时间是常数。例如，考虑以下代码片段：

```py
    i = 1 
    while i <= n: 
        i=i * 2 
        print(i) 
```

注意`i`在每次迭代中都会加倍，如果我们以*n*=10 运行这个程序，我们会看到它打印出四个数字；2、4、8 和 16。如果我们将*n*加倍，我们会看到它打印出五个数字。随着*n*的每次加倍，迭代次数只增加了 1。如果我们假设*k*次迭代，我们可以写成如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e7efcb8e-d08f-4c5c-8ba8-ff765a96cdbf.png)

由此我们可以得出总时间 = **O**(*log(n)*)。

尽管大 O 是渐近分析中最常用的符号，但还有两个相关的符号应该简要提到。它们是 Omega 符号和 Theta 符号。

# Omega 符号（Ω）

大 O 符号描述了上界的情况，Omega 符号描述了**紧密的下界**。定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0be56dbf-c79b-4d73-b1f6-7b1411bb36f6.png)

目标是找到与给定算法 T(*n*)的增长率相等或小于的最大增长率。

# Theta 符号（ϴ）

通常情况下，给定函数的上界和下界是相同的，Theta 符号的目的就是确定这种情况是否存在。定义如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/1da75a4c-29dc-4ab9-a25e-ae5b5209db08.png)

虽然 Omega 和 Theta 符号需要完全描述增长率，但最实用的是大 O 符号，这是你经常会看到的。

# 摊销分析

通常我们对单个操作的时间复杂度不太感兴趣，而是更关注操作序列的平均运行时间。这被称为摊销分析。它与平均情况分析不同，我们很快会讨论，因为它不对输入值的数据分布做任何假设。但是，它考虑了数据结构的状态变化。例如，如果列表已排序，则任何后续查找操作都应该更快。摊销分析可以考虑数据结构的状态变化，因为它分析操作序列，而不仅仅是聚合单个操作。

摊销分析通过对操作序列中的每个操作施加人为成本，然后组合这些成本，找到运行时间的上界。序列的人为成本考虑到初始昂贵的操作可能使后续操作变得更便宜。

当我们有少量昂贵的操作，比如排序，和大量更便宜的操作，比如查找时，标准的最坏情况分析可能导致过于悲观的结果，因为它假设每次查找都必须比较列表中的每个元素直到找到匹配项。我们应该考虑到一旦我们对列表进行排序，我们可以使后续的查找操作变得更便宜。

到目前为止，在我们的运行时间分析中，我们假设输入数据是完全随机的，并且只关注输入大小对运行时间的影响。算法分析还有另外两种常见的方法：

+   平均情况分析

+   基准测试

平均情况分析根据对各种输入值的相对频率的一些假设，找到平均运行时间。使用真实世界的数据，或者模拟真实世界数据的分布，往往是基于特定数据分布的，然后计算平均运行时间。

基准测试就是有一组约定的典型输入，用于衡量性能。基准测试和平均时间分析都依赖于一些领域知识。我们需要知道典型或预期的数据集是什么。最终，我们将尝试通过微调到一个非常具体的应用设置来改善性能。

让我们看一种简单的方法来衡量算法的运行时间性能。这可以通过简单地计算算法在不同输入大小下完成所需的时间来实现。正如我们之前提到的，这种衡量运行时间性能的方式取决于它运行的硬件。显然，更快的处理器会给出更好的结果，然而，随着输入大小的增加，它们的相对增长率仍将保留算法本身的特征，而不是它运行的硬件。绝对时间值会因硬件（和软件）平台的不同而有所不同；然而，它们的相对增长仍将受到算法的时间复杂度的限制。

让我们以一个嵌套循环的简单例子来说明。很明显，这个算法的时间复杂度是 O(n²)，因为在外部循环的每 n 次迭代中，内部循环也有 n 次迭代。例如，我们简单的嵌套 for 循环由内部循环上执行的简单语句组成：

```py
    def nest(n): 
        for i in range(n): 
            for j in range(n): 
                i+j 
```

以下代码是一个简单的测试函数，它使用不断增加的`n`值运行嵌套函数。在每次迭代中，我们使用`timeit.timeit`函数计算该函数完成所需的时间。在这个例子中，`timeit`函数接受三个参数，一个表示要计时的函数的字符串表示，一个导入嵌套函数的设置函数，以及一个`int`参数，表示执行主语句的次数。由于我们对嵌套函数完成所需的时间相对于输入大小`n`感兴趣，因此对于我们的目的来说，在每次迭代中调用一次嵌套函数就足够了。以下函数返回每个 n 值的计算运行时间的列表：

```py
    import timeit  
    def test2(n): 
        ls=[] 
        for n in range(n): 
            t=timeit.timeit("nest(" + str(n) +")", setup="from __main__ import nest", number = 1) 
            ls.append(t) 
        return ls    
```

在以下代码中，我们运行 test2 函数并绘制结果，以及适当缩放的 n²函数进行比较，用虚线表示：

```py
    import matplotlib.pyplot as plt 
    n=1000 
    plt.plot(test2(n)) 
    plt.plot([x*x/10000000 for x in range(n)]) 
```

这给出了以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/44c2f6b6-a425-4914-93b4-03030c9acde8.png)

正如我们所看到的，这基本上符合我们的预期。应该记住，这既代表了算法本身的性能，也代表了底层软件和硬件平台的行为，这一点可以从测量运行时间的变化和运行时间的相对大小看出。显然，更快的处理器会导致更快的运行时间，而性能也会受到其他运行进程、内存限制、时钟速度等的影响。

# 摘要

在本章中，我们对算法设计进行了一般概述。重要的是，我们看到了一种平台无关的方法来衡量算法的性能。我们看了一些不同的算法问题解决方法。我们看了一种递归相乘大数的方法，也看了归并排序的递归方法。我们看到了如何使用回溯进行穷举搜索和生成字符串。我们还介绍了基准测试的概念以及衡量运行时间的简单平台相关方法。在接下来的章节中，我们将参考特定的数据结构重新讨论这些想法。在下一章中，我们将讨论链表和其他指针结构。


# 第七章：列表和指针结构

你已经在 Python 中看到了列表。它们方便而强大。通常，每当你需要在列表中存储东西时，你使用 Python 的内置列表实现。然而，在本章中，我们更感兴趣的是理解列表的工作原理。因此，我们将研究列表的内部。正如你将注意到的，有不同类型的列表。

Python 的列表实现旨在强大并包含几种不同的用例。我们将对列表的定义更加严格。节点的概念对列表非常重要。我们将在本章讨论它们，但这个概念将以不同的形式在本书的其余部分中再次出现。

本章的重点将是以下内容：

+   了解 Python 中的指针

+   处理节点的概念

+   实现单向、双向和循环链表

在本章中，我们将处理相当多的指针。因此，提醒自己这些是有用的。首先，想象一下你有一所房子想要出售。由于时间不够，你联系了一个中介来寻找感兴趣的买家。所以你拿起你的房子，把它带到中介那里，中介会把房子带给任何可能想要购买它的人。你觉得荒谬吗？现在想象一下你有一些 Python 函数，用于处理图像。所以你在函数之间传递高分辨率图像数据。

当然，你不会把你的房子随身携带。你会把房子的地址写在一张废纸上，交给中介。房子还在原地，但包含房子方向的纸条在传递。你甚至可能在几张纸上写下来。每张纸都足够小，可以放在钱包里，但它们都指向同一所房子。

事实证明，在 Python 领域并没有太大的不同。那些大型图像文件仍然在内存中的一个地方。你所做的是创建变量，保存这些图像在内存中的位置。这些变量很小，可以在不同的函数之间轻松传递。

这就是指针的巨大好处：它们允许你用简单的内存地址指向潜在的大内存段。

指针存在于计算机的硬件中，被称为间接寻址。

在 Python 中，你不直接操作指针，不像其他一些语言，比如 C 或 Pascal。这导致一些人认为 Python 中不使用指针。这是大错特错。考虑一下在 Python 交互式 shell 中的这个赋值：

```py
    >>> s = set()
```

我们通常会说`s`是 set 类型的变量。也就是说，`s`是一个集合。然而，这并不严格正确。变量`s`实际上是一个引用（一个“安全”的指针）指向一个集合。集合构造函数在内存中创建一个集合，并返回该集合开始的内存位置。这就是存储在`s`中的内容。

Python 将这种复杂性隐藏起来。我们可以安全地假设`s`是一个集合，并且一切都运行正常。

# 数组

数组是数据的顺序列表。顺序意味着每个元素都存储在前一个元素的后面。如果你的数组非常大，而且内存不足，可能找不到足够大的存储空间来容纳整个数组。这将导致问题。

当然，硬币的另一面是数组非常快。由于每个元素都紧随前一个元素在内存中，不需要在不同的内存位置之间跳转。在选择列表和数组在你自己的实际应用程序中时，这可能是一个非常重要的考虑因素。

# 指针结构

与数组相反，指针结构是可以在内存中分散的项目列表。这是因为每个项目包含一个或多个链接到结构中其他项目的链接。这些链接的类型取决于我们拥有的结构类型。如果我们处理的是链表，那么我们将有链接到结构中下一个（可能是上一个）项目的链接。在树的情况下，我们有父子链接以及兄弟链接。在基于瓦片的游戏中，游戏地图由六边形构建，每个节点将链接到最多六个相邻的地图单元。

指针结构有几个好处。首先，它们不需要顺序存储空间。其次，它们可以从小开始，随着向结构中添加更多节点而任意增长。

然而，这是有代价的。如果你有一个整数列表，每个节点将占据一个整数的空间，以及额外的整数用于存储指向下一个节点的指针。

# 节点

在列表（以及其他几种数据结构）的核心是节点的概念。在我们进一步之前，让我们考虑一下这个想法。

首先，我们将创建一些字符串：

```py
>>> a = "eggs"
>>> b = "ham"
>>> c = "spam"
```

现在你有三个变量，每个变量都有一个唯一的名称、类型和值。我们没有的是一种方法来说明变量之间的关系。节点允许我们这样做。节点是数据的容器，以及一个或多个指向其他节点的链接。链接是一个指针。

一个简单类型的节点只有一个指向下一个节点的链接。

当然，根据我们对指针的了解，我们意识到这并不完全正确。字符串并没有真正存储在节点中，而是指向实际字符串的指针：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/f0120953-dde0-440a-b6e4-c435d9aaa949.jpg)

因此，这个简单节点的存储需求是两个内存地址。节点的数据属性是指向字符串`eggs`和`ham`的指针。

# 查找终点

我们创建了三个节点：一个包含**eggs**，一个**ham**，另一个**spam**。**eggs**节点指向**ham**节点，**ham**节点又指向**spam**节点。但**spam**节点指向什么？由于这是列表中的最后一个元素，我们需要确保它的下一个成员有一个清晰的值。

如果我们使最后一个元素指向空，则我们使这一事实清楚。在 Python 中，我们将使用特殊值`None`来表示空：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/51d9ca4b-c0d8-4d9b-96fc-ff09f98627c3.jpg)

最后一个节点的下一个指针指向 None。因此它是节点链中的最后一个节点。

# 节点

这是我们迄今为止讨论的一个简单节点实现：

```py
    class Node: 
        def __init__(self, data=None): 
            self.data = data 
            self.next = None 
```

不要将节点的概念与 Node.js 混淆，Node.js 是一种使用 JavaScript 实现的服务器端技术。

`next`指针被初始化为`None`，这意味着除非你改变`next`的值，否则节点将成为一个终点。这是一个好主意，这样我们就不会忘记正确终止列表。

你可以根据需要向`node`类添加其他内容。只需记住节点和数据之间的区别。如果你的节点将包含客户数据，那么创建一个`Customer`类并将所有数据放在那里。

你可能想要实现`__str__`方法，这样当节点对象传递给 print 时，它调用包含对象的`__str__`方法：

```py
    def __str__(self): 
        return str(data) 
```

# 其他节点类型

我们假设节点具有指向下一个节点的指针。这可能是最简单的节点类型。然而，根据我们的要求，我们可以创建许多其他类型的节点。

有时我们想从 A 到 B，但同时也想从 B 到 A。在这种情况下，我们除了下一个指针外还添加了一个前一个指针：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/124fe45b-0d55-4db6-b881-2ee91e2ed608.jpg)

从图中可以看出，我们让最后一个节点和第一个节点都指向`None`，表示我们已经到达它们作为列表端点的边界。第一个节点的前指针指向 None，因为它没有前任，就像最后一个项目的后指针指向`None`一样，因为它没有后继节点。

您可能还在为基于瓦片的游戏创建瓦片。在这种情况下，您可能使用北、南、东和西代替前一个和后一个。指针的类型更多，但原理是相同的。地图末尾的瓦片将指向`None`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/117da9a1-faa1-4324-a90b-72c8d7041c7f.jpg)

您可以根据需要扩展到任何程度。如果您需要能够向西北、东北、东南和西南移动，您只需将这些指针添加到您的`node`类中。

# 单链表

单链表是一个只有两个连续节点之间的指针的列表。它只能以单个方向遍历，也就是说，您可以从列表中的第一个节点移动到最后一个节点，但不能从最后一个节点移动到第一个节点。

实际上，我们可以使用之前创建的`node`类来实现一个非常简单的单链表：

```py
    >>> n1 = Node('eggs')
    >>> n2 = Node('ham')
    >>> n3 = Node('spam')
```

接下来，我们将节点链接在一起，使它们形成一个*链*：

```py
    >>> n1.next = n2
    >>> n2.next = n3
```

要遍历列表，您可以执行以下操作。我们首先将变量`current`设置为列表中的第一个项目：

```py
    current = n1
    while current:
        print(current.data)
        current = current.next 
```

在循环中，我们打印当前元素，然后将当前设置为指向列表中的下一个元素。我们一直这样做，直到我们到达列表的末尾。

但是，这种简单的列表实现存在几个问题：

+   程序员需要太多的手动工作

+   这太容易出错了（这是第一个问题的结果）

+   列表的内部工作方式对程序员暴露得太多

我们将在以下部分解决所有这些问题。

# 单链表类

列表显然是一个与节点不同的概念。因此，我们首先创建一个非常简单的类来保存我们的列表。我们将从一个持有对列表中第一个节点的引用的构造函数开始。由于此列表最初为空，因此我们将首先将此引用设置为`None`：

```py
    class SinglyLinkedList:
         def __init__(self):
             self.tail = None 
```

# 附加操作

我们需要执行的第一个操作是向列表附加项目。这个操作有时被称为插入操作。在这里，我们有机会隐藏`Node`类。我们的`list`类的用户实际上不应该与 Node 对象进行交互。这些纯粹是内部使用。

第一次尝试`append()`方法可能如下所示：

```py
    class SinglyLinkedList:
         # ...

         def append(self, data):
             # Encapsulate the data in a Node
             node = Node(data)

             if self.tail == None:
                 self.tail = node
             else:
                 current = self.tail
                 while current.next:
                     current = current.next
                 current.next = node 
```

我们将数据封装在一个节点中，因此它现在具有下一个指针属性。从这里开始，我们检查列表中是否存在任何现有节点（即`self.tail`指向一个节点）。如果没有，我们将新节点设置为列表的第一个节点；否则，通过遍历列表找到插入点，将最后一个节点的下一个指针更新为新节点。

我们可以附加一些项目：

```py
>>> words = SinglyLinkedList()
 >>> words.append('egg')
 >>> words.append('ham')
 >>> words.append('spam')
```

列表遍历将更多或更少地像以前一样工作。您将从列表本身获取列表的第一个元素：

```py
>>> current = words.tail
>>> while current:
        print(current.data) 
        current = current.next
```

# 更快的附加操作

在上一节中，附加方法存在一个大问题：它必须遍历整个列表以找到插入点。当列表中只有几个项目时，这可能不是问题，但等到您需要添加成千上万个项目时再等等。每次附加都会比上一次慢一点。一个**O**(n)证明了我们当前的`append`方法实际上会有多慢。

为了解决这个问题，我们将存储的不仅是列表中第一个节点的引用，还有最后一个节点的引用。这样，我们可以快速地在列表的末尾附加一个新节点。附加操作的最坏情况运行时间现在从**O**(n)减少到**O**(1)。我们所要做的就是确保前一个最后一个节点指向即将附加到列表中的新节点。以下是我们更新后的代码：

```py
    class SinglyLinkedList:
         def __init__(self): 
             # ...
             self.tail = None

         def append(self, data):
            node = Node(data)
            if self.head:
                self.head.next = node
                self.head = node
            else:
                self.tail = node
                self.head = node 
```

注意正在使用的约定。我们附加新节点的位置是通过`self.head`。`self.tail`变量指向列表中的第一个节点。

# 获取列表的大小

我们希望通过计算节点数来获取列表的大小。我们可以通过遍历整个列表并在遍历过程中增加一个计数器来实现这一点：

```py
    def size(self):
         count = 0
         current = self.tail
         while current:
             count += 1
             current = current.next
         return count 
```

这样做是可以的，但列表遍历可能是一个昂贵的操作，我们应该尽量避免。因此，我们将选择另一种重写方法。我们在`SinglyLinkedList`类中添加一个 size 成员，在构造函数中将其初始化为 0。然后我们在`append`方法中将 size 增加一：

```py
class SinglyLinkedList:
     def __init__(self):
         # ...
         self.size = 0

     def append(self, data):
         # ...
         self.size += 1 
```

因为我们现在只读取节点对象的 size 属性，而不使用循环来计算列表中的节点数，所以我们可以将最坏情况的运行时间从**O**(n)减少到**O**(1)。

# 改进列表遍历

如果您注意到我们如何遍历我们的列表。那里我们仍然暴露给`node`类的地方。我们需要使用`node.data`来获取节点的内容和`node.next`来获取下一个节点。但我们之前提到客户端代码不应该需要与 Node 对象进行交互。我们可以通过创建一个返回生成器的方法来实现这一点。它看起来如下：

```py
    def iter(self):
        current = self.tail
        while current:
            val = current.data
            current = current.next
            yield val  
```

现在列表遍历变得简单得多，看起来也好得多。我们可以完全忽略列表之外有一个叫做 Node 的东西：

```py
    for word in words.iter():
        print(word) 
```

请注意，由于`iter()`方法产生节点的数据成员，我们的客户端代码根本不需要担心这一点。

# 删除节点

列表上的另一个常见操作是删除节点。这可能看起来很简单，但我们首先必须决定如何选择要删除的节点。是按索引号还是按节点包含的数据？在这里，我们将选择按节点包含的数据删除节点。

以下是从列表中删除节点时考虑的一个特殊情况的图示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/681a0c61-f4fc-4b58-bd9d-ff3ade3c9d61.jpg)

当我们想要删除两个其他节点之间的节点时，我们所要做的就是将前一个节点直接指向其下一个节点的后继节点。也就是说，我们只需像前面的图像中那样将要删除的节点从链中切断。

以下是`delete()`方法的实现可能是这样的：

```py
    def delete(self, data):
        current = self.tail
        prev = self.tail
        while current:
            if current.data == data:
                if current == self.tail:
                    self.tail = current.next
                else:
                    prev.next = current.next
                self.size -= 1
                return
            prev = current
            current = current.next 
```

删除节点应该需要**O**(n)的时间。

# 列表搜索

我们可能还需要一种方法来检查列表是否包含某个项目。由于我们之前编写的`iter()`方法，这种方法实现起来相当容易。循环的每一次通过都将当前数据与正在搜索的数据进行比较。如果找到匹配项，则返回`True`，否则返回`False`：

```py
def search(self, data):
     for node in self.iter():
         if data == node:
             return True
     return False  
```

# 清空列表

我们可能希望快速清空列表。幸运的是，这非常简单。我们只需将指针`head`和`tail`设置为`None`即可：

```py
def clear(self): 
       """ Clear the entire list. """ 
       self.tail = None 
       self.head = None 
```

一举两得，我们将列表的`tail`和`head`指针上的所有节点都变成了孤立的。这会导致中间所有的节点都变成了孤立的。

# 双向链表

现在我们对单向链表有了扎实的基础，知道了可以对其执行的操作类型，我们现在将把注意力转向更高一级的双向链表主题。

双向链表在某种程度上类似于单向链表，因为我们利用了将节点串联在一起的相同基本思想。在单向链表中，每个连续节点之间存在一个链接。双向链表中的节点有两个指针：指向下一个节点和指向前一个节点的指针：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/48886177-4080-49b0-bc7b-0a8a995fc324.jpg)

单向链表中的节点只能确定与其关联的下一个节点。但是被引用的节点或下一个节点无法知道是谁在引用它。方向的流动是**单向的**。

在双向链表中，我们为每个节点添加了不仅引用下一个节点而且引用前一个节点的能力。

让我们检查一下两个连续节点之间存在的连接性质，以便更好地理解：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/03bff824-7bea-410e-acb8-a1d607bca4db.jpg)

由于存在指向下一个和前一个节点的两个指针，双向链表具有某些能力。

双向链表可以在任何方向遍历。根据正在执行的操作，双向链表中的节点可以在必要时轻松地引用其前一个节点，而无需指定变量来跟踪该节点。因为单向链表只能在一个方向上遍历，有时可能意味着移动到列表的开始或开头，以便影响列表中隐藏的某些更改。

由于立即可以访问下一个和前一个节点，删除操作要容易得多，后面在本章中会看到。

# 双向链表节点

创建一个类来捕获双向链表节点的 Python 代码，在其初始化方法中包括`prev`、`next`和`data`实例变量。当新创建一个节点时，所有这些变量默认为`None`：

```py
    class Node(object): 
        def __init__(self, data=None, next=None, prev=None): 
           self.data = data 
           self.next = next 
           self.prev = prev 
```

`prev`变量保存对前一个节点的引用，而`next`变量继续保存对下一个节点的引用。

# 双向链表

仍然很重要的是创建一个类，以捕获我们的函数将要操作的数据：

```py
    class DoublyLinkedList(object):
       def __init__(self):
           self.head = None
           self.tail = None
           self.count = 0
```

为了增强`size`方法，我们还将`count`实例变量设置为 0。当我们开始向列表中插入节点时，`head`和`tail`将指向列表的头部和尾部。

我们采用了一个新的约定，其中`self.head`指向列表的起始节点，而`self.tail`指向列表中最新添加的节点。这与我们在单向链表中使用的约定相反。关于头部和尾部节点指针的命名没有固定的规则。

双向链表还需要提供返回列表大小、插入列表和从列表中删除节点的函数。我们将检查一些执行此操作的代码。让我们从`append`操作开始。

# 追加操作

在`append`操作期间，重要的是检查`head`是否为`None`。如果是`None`，则意味着列表为空，并且应该将`head`设置为指向刚创建的节点。通过头部，列表的尾部也指向新节点。在这一系列步骤结束时，`head`和`tail`现在将指向同一个节点：

```py
    def append(self, data): 
        """ Append an item to the list. """ 

           new_node = Node(data, None, None) 
           if self.head is None: 
               self.head = new_node 
               self.tail = self.head 
           else: 
               new_node.prev = self.tail 
               self.tail.next = new_node 
               self.tail = new_node 

               self.count += 1 
```

以下图表说明了在向空列表添加新节点时，双向链表的头部和尾部指针。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/4726485a-16d3-40e4-ae32-b63afef3b054.jpg)

算法的`else`部分仅在列表不为空时执行。新节点的前一个变量设置为列表的尾部：

```py
    new_node.prev = self.tail 
```

尾部的下一个指针（或变量）设置为新节点：

```py
    self.tail.next = new_node 
```

最后，我们更新尾部指针指向新节点：

```py
    self.tail = new_node 
```

由于`append`操作将节点数增加了一个，我们将计数器增加了一个：

```py
    self.count += 1 
```

`append`操作的视觉表示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e7446f9f-dddb-4220-99f4-182bc7fe4416.jpg)

# 删除操作

与单向链表不同，我们需要在遍历整个列表的时候跟踪先前遇到的节点，双向链表避免了这一步。这是通过使用前一个指针实现的。

从双向链表中删除节点的算法在完成节点删除之前，为基本上四种情况提供了支持。这些是：

+   当根本找不到搜索项时

+   当搜索项在列表的开头找到时

+   当搜索项在列表的尾部找到时

+   当搜索项在列表的中间找到时

当其`data`实例变量与传递给用于搜索节点的方法的数据匹配时，将识别要移除的节点。如果找到匹配的节点并随后删除，则将变量`node_deleted`设置为`True`。任何其他结果都会导致`node_deleted`被设置为`False`：

```py
    def delete(self, data): 
        current = self.head 
        node_deleted = False 
        ...    
```

在`delete`方法中，`current`变量被设置为列表的头部（即指向列表的`self.head`）。然后使用一组`if...else`语句搜索列表的各个部分，以找到具有指定数据的节点。

首先搜索`head`节点。由于`current`指向`head`，如果`current`为 None，则假定列表没有节点，甚至无法开始搜索要删除的节点：

```py
    if current is None: 
        node_deleted = False     
```

然而，如果`current`（现在指向头部）包含正在搜索的数据，那么`self.head`被设置为指向`current`的下一个节点。由于现在头部后面没有节点了，`self.head.prev`被设置为`None`：

```py
    elif current.data == data: 
        self.head = current.next 
        self.head.prev = None 
        node_deleted = True 
```

如果要删除的节点位于列表的尾部，将采用类似的策略。这是第三个语句，搜索要删除的节点可能位于列表末尾的可能性：

```py
    elif self.tail.data == data: 
        self.tail = self.tail.prev 
        self.tail.next = None 
        node_deleted = True 
```

最后，查找并删除节点的算法循环遍历节点列表。如果找到匹配的节点，`current`的前一个节点将连接到`current`的下一个节点。在这一步之后，`current`的下一个节点将连接到`current`的前一个节点：

```py
else
    while current: 
        if current.data == data: 
            current.prev.next = current.next 
            current.next.prev = current.prev 
            node_deleted = True 
        current = current.next 
```

然后在评估所有`if-else`语句之后检查`node_delete`变量。如果任何`if-else`语句更改了这个变量，那么意味着从列表中删除了一个节点。因此，计数变量减 1：

```py
    if node_deleted: 
        self.count -= 1 
```

作为删除列表中嵌入的节点的示例，假设存在三个节点 A、B 和 C。要删除列表中间的节点 B，我们将使 A 指向 C 作为它的下一个节点，同时使 C 指向 A 作为它的前一个节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/95e53e49-1f8e-4c1c-82ae-950c6bd20d8b.jpg)

在这样的操作之后，我们得到以下列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/290796b6-c426-4da7-81d2-0b4fd7fc3a65.jpg)

# 列表搜索

搜索算法类似于单向链表中`search`方法的算法。我们调用内部方法`iter()`返回所有节点中的数据。当我们循环遍历数据时，每个数据都与传入`contain`方法的数据进行匹配。如果匹配，则返回`True`，否则返回`False`以表示未找到匹配项：

```py
    def contain(self, data): 
        for node_data in self.iter(): 
            if data == node_data: 
                return True 
            return False 
```

我们的双向链表对于`append`操作具有**O**(1)，对于`delete`操作具有**O**(n)。

# 循环列表

循环列表是链表的一种特殊情况。它是一个端点连接的列表。也就是说，列表中的最后一个节点指向第一个节点。循环列表可以基于单向链表和双向链表。对于双向循环链表，第一个节点还需要指向最后一个节点。

在这里，我们将看一个单向循环链表的实现。一旦你掌握了基本概念，实现双向循环链表就应该很简单了。

我们可以重用我们在单链表部分创建的`node`类。事实上，我们也可以重用`SinglyLinkedList`类的大部分部分。因此，我们将专注于循环列表实现与普通单链表不同的方法。

# 附加元素

当我们向循环列表附加一个元素时，我们需要确保新节点指向尾节点。这在以下代码中得到了证明。与单链表实现相比，多了一行额外的代码：

```py
     def append(self, data): 
           node = Node(data) 
           if self.head: 
               self.head.next = node 
               self.head = node 
           else: 
               self.head = node 
               self.tail = node 
           self.head.next = self.tail 
           self.size += 1 
```

# 删除元素

我们可能认为我们可以遵循与附加相同的原则，并确保头部指向尾部。这将给我们以下实现：

```py
   def delete(self, data): 
       current = self.tail 
       prev = self.tail 
       while current: 
           if current.data == data: 
               if current == self.tail: 
                   self.tail = current.next 
                   self.head.next = self.tail 
               else: 
                   prev.next = current.next 
               self.size -= 1 
               return 
           prev = current 
           current = current.next 
```

与以前一样，只有一行需要更改。只有在删除尾节点时，我们需要确保头节点被更新为指向新的尾节点。

然而，这段代码存在一个严重的问题。在循环列表的情况下，我们不能循环直到当前变为`None`，因为那永远不会发生。如果您删除一个现有节点，您不会看到这一点，但是尝试删除一个不存在的节点，您将陷入无限循环。

因此，我们需要找到一种不同的方法来控制`while`循环。我们不能检查当前是否已经到达头部，因为那样它就永远不会检查最后一个节点。但是我们可以使用`prev`，因为它落后于当前一个节点。然而，有一个特殊情况。在第一个循环迭代中，`current`和`prev`将指向同一个节点，即尾节点。我们希望确保循环在这里运行，因为我们需要考虑只有一个节点的情况。更新后的`delete`方法现在如下所示：

```py
def delete(self, data): 
        current = self.tail 
        prev = self.tail 
        while prev == current or prev != self.head: 
            if current.data == data: 
                if current == self.tail: 
                    self.tail = current.next 
                    self.head.next = self.tail 
                else: 
                    prev.next = current.next 
                self.size -= 1 
                return 
            prev = current 
            current = current.next 
```

# 遍历循环列表

您不需要修改`iter()`方法。它对于我们的循环列表可以完美地工作。但是在遍历循环列表时，您需要设置一个退出条件，否则您的程序将陷入循环。以下是一种方法，可以使用计数器变量来实现：

```py
    words = CircularList() 
    words.append('eggs') 
    words.append('ham') 
    words.append('spam') 

    counter = 0 
    for word in words.iter(): 
       print(word) 
       counter += 1 
       if counter > 1000: 
           break 
```

一旦我们打印出 1,000 个元素，我们就跳出循环。

# 总结

在本章中，我们已经研究了链表。我们研究了构成列表的概念，如节点和指向其他节点的指针。我们实现了在这些类型的列表上发生的主要操作，并看到了它们的最坏情况运行时间是如何比较的。

在下一章中，我们将看两种通常使用列表实现的其他数据结构：栈和队列。


# 第八章：堆栈和队列

在本章中，我们将在上一章中学到的技能的基础上构建，以创建特殊的列表实现。我们仍然坚持线性结构。在接下来的章节中，我们将介绍更复杂的数据结构。

在本章中，我们将研究以下内容：

+   实现堆栈和队列

+   堆栈和队列的一些应用

# 堆栈

堆栈是一种经常被比作一堆盘子的数据结构。如果你刚刚洗了一个盘子，你把它放在堆叠的顶部。当你需要一个盘子时，你从堆叠的顶部取出它。因此，最后添加到堆叠的盘子将首先从堆叠中移除。因此，堆栈是**后进先出**（**LIFO**）结构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/f9b6f83e-4f80-4394-8403-1be5aec87197.jpg)

上图描述了一堆盘子的堆栈。只有将一个盘子放在堆叠的顶部才可能添加一个盘子。从盘子堆中移除一个盘子意味着移除堆顶上的盘子。

堆栈上执行的两个主要操作是`push`和`pop`。当元素添加到堆栈顶部时，它被推送到堆栈上。当元素从堆栈顶部取出时，它被弹出堆栈。有时使用的另一个操作是`peek`，它可以查看堆栈上的元素而不将其弹出。

堆栈用于许多事情。堆栈的一个非常常见的用途是在函数调用期间跟踪返回地址。让我们想象一下我们有以下小程序：

```py
def b(): 
    print('b') 

def a(): 
    b() 

a() 
print("done") 
```

当程序执行到对`a()`的调用时，首先将以下指令的地址推送到堆栈上，然后跳转到`a`。在`a`内部，调用`b()`，但在此之前，返回地址被推送到堆栈上。一旦在`b()`中，函数完成后，返回地址就会从堆栈中弹出，这将带我们回到`a()`。当`a`完成时，返回地址将从堆栈中弹出，这将带我们回到`print`语句。

实际上，堆栈也用于在函数之间传递数据。假设你的代码中的某处有以下函数调用：

```py
   somefunc(14, 'eggs', 'ham', 'spam') 
```

将发生的是`14, 'eggs', 'ham'`和`'spam'`将依次被推送到堆栈上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ada829bd-7a36-417d-8b9c-0c959bd9e8ed.jpg)

当代码跳转到函数时，`a, b, c, d`的值将从堆栈中弹出。首先将`spam`元素弹出并分配给`d`，然后将`"ham"`分配给`c`，依此类推：

```py
    def somefunc(a, b, c, d): 
        print("function executed")
```

# 堆栈实现

现在让我们来学习 Python 中堆栈的实现。我们首先创建一个`node`类，就像我们在上一章中使用列表一样：

```py
class Node: 
    def __init__(self, data=None): 
        self.data = data 
        self.next = None 
```

现在这对你来说应该很熟悉：一个节点保存数据和列表中下一个项目的引用。我们将实现一个堆栈而不是列表，但节点链接在一起的原则仍然适用。

现在让我们来看一下`stack`类。它开始类似于单链表。我们需要知道堆栈顶部的节点。我们还想跟踪堆栈中节点的数量。因此，我们将向我们的类添加这些字段：

```py
class Stack: 
    def __init__(self): 
        self.top = None 
        self.size = 0 
```

# 推送操作

`push`操作用于将元素添加到堆栈的顶部。以下是一个实现：

```py
   def push(self, data): 
       node = Node(data) 
       if self.top: 
           node.next = self.top 
           self.top = node                 
       else: 
           self.top = node 
       self.size += 1 
```

在下图中，在创建新节点后没有现有节点。因此`self.top`将指向这个新节点。`if`语句的`else`部分保证了这一点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/8c66894e-0d5c-43ff-af8d-bc571afa8205.jpg)

在我们有一个现有的堆栈的情况下，我们移动`self.top`，使其指向新创建的节点。新创建的节点必须有其**next**指针，指向堆栈上原来的顶部节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/6eb72349-1b93-4d2c-ae5e-775a76109b02.jpg)

# 弹出操作

现在我们需要一个`pop`方法来从堆栈中移除顶部元素。在这样做的同时，我们需要返回顶部元素。如果没有更多元素，我们将使堆栈返回`None`：

```py
    def pop(self): 
        if self.top: 
            data = self.top.data 
            self.size -= 1  
            if self.top.next: 
                self.top = self.top.next 
            else: 
                self.top = None 
            return data 
        else: 
            return None 
```

这里需要注意的是内部的`if`语句。如果顶部节点的**next**属性指向另一个节点，那么我们必须将堆栈的顶部指向该节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e832ddc2-57ec-4252-ab91-d1031c910468.jpg)

当堆栈中只有一个节点时，`pop`操作将按以下方式进行：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/068806f4-31b6-4dd2-8e06-1fe00b7a30a3.jpg)

移除这样的节点会导致`self.top`指向`None`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/42040b37-cc5f-4fb9-9e0b-f9789f7200aa.jpg)

# Peek

正如我们之前所说，我们也可以添加一个`peek`方法。这将只返回堆栈的顶部而不将其从堆栈中移除，使我们能够查看堆栈的顶部元素而不改变堆栈本身。这个操作非常简单。如果有一个顶部元素，返回它的数据，否则返回`None`（以便`peek`的行为与`pop`的行为相匹配）：

```py
    def peek(self): 
        if self.top 
            return self.top.data 
        else: 
            return None 
```

# 括号匹配应用程序

现在让我们看一个例子，说明我们如何使用我们的堆栈实现。我们将编写一个小函数，用于验证包含括号（（，[或{）的语句是否平衡，也就是说，闭合括号的数量是否与开放括号的数量匹配。它还将确保一个括号对确实包含在另一个括号中：

```py
    def check_brackets(statement): 
        stack = Stack() 
        for ch in statement: 
            if ch in ('{', '[', '('): 
                stack.push(ch) 
            if ch in ('}', ']', ')'): 
                last = stack.pop() 
            if last is '{' and ch is '}': 
                continue 
            elif last is '[' and ch is ']': 
                continue 
            elif last is '(' and ch is ')': 
                continue 
            else: 
                return False 
    if stack.size > 0: 
        return False 
    else: 
        return True 
```

我们的函数解析传递给它的语句中的每个字符。如果它得到一个开放括号，它将其推送到堆栈上。如果它得到一个闭合括号，它将堆栈的顶部元素弹出并比较两个括号，以确保它们的类型匹配：（应该匹配），[应该匹配]，{应该匹配}。如果它们不匹配，我们返回`False`，否则我们继续解析。

一旦我们到达语句的末尾，我们需要进行最后一次检查。如果堆栈为空，那么一切正常，我们可以返回`True`。但是如果堆栈不为空，那么我们有一些没有匹配的闭合括号，我们将返回`False`。我们可以用以下小代码测试括号匹配器：

```py
sl = ( 
   "{(foo)(bar)}hellois)a)test", 
   "{(foo)(bar)}hellois)atest", 
   "{(foo)(bar)}hellois)a)test))" 
) 
for s in sl: 
   m = check_brackets(s) 
   print("{}: {}".format(s, m)) 
```

只有三个语句中的第一个应该匹配。当我们运行代码时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/348b931f-31df-4d67-a398-4e9d96f6db4f.png)

`True`，`False`，`False`。代码有效。总之，堆栈数据结构的`push`和`pop`操作吸引了**O**(*1*)。堆栈数据结构非常简单，但在现实世界中用于实现整个范围的功能。浏览器上的后退和前进按钮是由堆栈实现的。为了能够在文字处理器中具有撤销和重做功能，也使用了堆栈。

# 队列

另一种特殊类型的列表是队列数据结构。这种数据结构与你在现实生活中习惯的常规队列没有什么不同。如果你曾经在机场排队或者在邻里商店等待你最喜欢的汉堡，那么你应该知道队列是如何工作的。

队列也是一个非常基本和重要的概念，因为许多其他数据结构都是基于它们构建的。

队列的工作方式是，通常第一个加入队列的人会首先得到服务，一切条件相同。首先进入，先出的首字母缩写**FIFO**最好地解释了这一点。当人们站在队列中等待轮到他们接受服务时，服务只在队列的前面提供。人们离开队列的唯一时机是在他们被服务时，这只发生在队列的最前面。严格定义来说，人们加入队列的前面是不合法的，因为那里正在为人们提供服务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/76e5d4fd-9702-49c6-ba06-ae510f3137f4.jpg)

要加入队列，参与者必须首先移动到队列中最后一个人的后面。队列的长度并不重要。这是队列接受新参与者的唯一合法或允许的方式。

我们作为人，所形成的队列并不遵循严格的规则。可能有人已经在队列中决定退出，甚至有其他人替代他们。我们的目的不是模拟真实队列中发生的所有动态。抽象出队列是什么以及它的行为方式使我们能够解决大量的挑战，特别是在计算方面。

我们将提供各种队列的实现，但所有实现都将围绕 FIFO 的相同思想。我们将称添加元素到队列的操作为 enqueue。要从队列中删除元素，我们将创建一个`dequeue`操作。每次入队一个元素时，队列的长度或大小增加一个。相反，出队项目会减少队列中的元素数量。

为了演示这两个操作，以下表格显示了从队列中添加和移除元素的效果：

| **队列操作** | **大小** | **内容** | **操作结果** |
| --- | --- | --- | --- |
| `Queue()` | 0 | `[]` | 创建队列对象 |
| `Enqueue` "Mark" | 1 | `['mark']` | Mark 添加到队列中 |
| `Enqueue` "John" | 2 | `['mark','john']` | John 添加到队列中 |
| `Size()` | 2 | `['mark','john']` | 返回队列中的项目数 |
| `Dequeue()` | 1 | `['mark']` | John 被出队并返回 |
| `Dequeue()` | 0 | `[]` | Mark 被出队并返回 |

# 基于列表的队列

为了将到目前为止讨论的有关队列的一切内容转化为代码，让我们继续使用 Python 的`list`类实现一个非常简单的队列。这有助于我们快速开发并了解队列。必须在队列上执行的操作封装在`ListQueue`类中：

```py
class ListQueue: 
    def __init__(self): 
        self.items = [] 
        self.size = 0 
```

在初始化方法`__init__`中，`items`实例变量设置为`[]`，这意味着创建时队列为空。队列的大小也设置为`zero`。更有趣的方法是`enqueue`和`dequeue`方法。

# 入队操作

`enqueue`操作或方法使用`list`类的`insert`方法在列表的前面插入项目（或数据）：

```py
    def enqueue(self, data): 
        self.items.insert(0, data) 
        self.size += 1 
```

请注意我们如何将插入到队列末尾的操作实现。索引 0 是任何列表或数组中的第一个位置。但是，在我们使用 Python 列表实现队列时，数组索引 0 是新数据元素插入队列的唯一位置。`insert`操作将列表中现有的数据元素向上移动一个位置，然后将新数据插入到索引 0 处创建的空间中。以下图形可视化了这个过程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/acda141e-486b-4998-acf8-d12153b3b79e.jpg)

为了使我们的队列反映新元素的添加，大小增加了一个：

```py
self.size += 1 
```

我们可以使用 Python 的`shift`方法在列表上实现“在 0 处插入”的另一种方法。归根结底，实现是练习的总体目标。

# 出队操作

`dequeue`操作用于从队列中移除项目。参考队列主题的介绍，此操作捕获了我们为首次加入队列并等待时间最长的客户提供服务的地方：

```py
    def dequeue(self):
        data = self.items.pop()
        self.size -= 1
        return data
```

Python 的`list`类有一个名为`pop()`的方法。`pop`方法执行以下操作：

1.  从列表中删除最后一个项目。

1.  将从列表中删除的项目返回给调用它的用户或代码。

列表中的最后一个项目被弹出并保存在`data`变量中。在方法的最后一行，返回数据。

考虑下图中的隧道作为我们的队列。执行`dequeue`操作时，从队列前面移除数据`1`的节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/6aa30ff3-231a-4368-b56d-b03352d05ef9.jpg)

队列中的结果元素如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/fcfb8cff-59f5-476f-bdd6-05a3c74ee882.jpg)对于`enqueue`操作，我们能说些什么呢？它在多个方面都非常低效。该方法首先必须将所有元素向后移动一个空间。想象一下，当列表中有 100 万个元素需要在每次向队列添加新元素时进行移动。这通常会使大型列表的 enqueue 过程非常缓慢。

# 基于堆栈的队列

使用两个堆栈的另一种队列实现方式。再次，Python 的`list`类将被用来模拟一个堆栈：

```py
class Queue: 
    def __init__(self): 
        self.inbound_stack = [] 
        self.outbound_stack = [] 
```

前述的`queue`类在初始化时将两个实例变量设置为空列表。这些堆栈将帮助我们实现队列。在这种情况下，堆栈只是允许我们在它们上面调用`push`和`pop`方法的 Python 列表。

`inbound_stack` 仅用于存储添加到队列中的元素。在此堆栈上不能执行其他操作。

# 入队操作

`enqueue`方法是向队列添加元素的方法：

```py
def enqueue(self, data): 
    self.inbound_stack.append(data) 
```

该方法是一个简单的方法，只接收客户端想要追加到队列中的`data`。然后将此数据传递给`queue`类中的`inbound_stack`的`append`方法。此外，`append`方法用于模拟`push`操作，将元素推送到堆栈顶部。

要将数据`enqueue`到`inbound_stack`，以下代码可以胜任：

```py
queue = Queue() 
queue.enqueue(5) 
queue.enqueue(6) 
queue.enqueue(7) 
print(queue.inbound_stack) 
```

队列中`inbound_stack`的命令行输出如下：

```py
[5, 6, 7]
```

# 出队操作

`dequeue`操作比其`enqueue`对应操作更复杂一些。添加到我们的队列中的新元素最终会出现在`inbound_stack`中。我们不是从`inbound_stack`中删除元素，而是将注意力转向`outbound_stack`。正如我们所说，只能通过`outbound_stack`从我们的队列中删除元素：

```py
    if not self.outbound_stack: 
        while self.inbound_stack: 
            self.outbound_stack.append(self.inbound_stack.pop()) 
    return self.outbound_stack.pop() 
```

`if`语句首先检查`outbound_stack`是否为空。如果不为空，我们继续通过执行以下操作来移除队列前端的元素：

```py
return self.outbound_stack.pop() 
```

如果`outbound_stack`为空，那么在弹出队列的前端元素之前，`inbound_stack`中的所有元素都将移动到`outbound_stack`中：

```py
while self.inbound_stack: 
    self.outbound_stack.append(self.inbound_stack.pop()) 
```

只要`inbound_stack`中有元素，`while`循环将继续执行。

语句`self.inbound_stack.pop()`将删除最新添加到`inbound_stack`中的元素，并立即将弹出的数据传递给`self.outbound_stack.append()`方法调用。

最初，我们的`inbound_stack`填充了元素**5**，**6**和**7**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0c9f8597-491f-473c-b03a-931f030741ea.jpg)

执行`while`循环的主体后，`outbound_stack`如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/b9f482bd-7bd5-4c63-9587-bb17ff0eecd6.jpg)![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/a8cd8bb4-4c0e-47a5-95c1-0e2ced3edb1b.png)

`dequeue`方法中的最后一行将返回`5`，作为对`outbound_stack`上的`pop`操作的结果：

```py
return self.outbound_stack.pop() 
```

这将使`outbound_stack`只剩下两个元素：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/18c49954-4199-454a-bec0-f7619ad6113c.jpg)

下次调用`dequeue`操作时，`while`循环将不会被执行，因为`outbound_stack`中没有元素，这使得外部的`if`语句失败。

在这种情况下，立即调用`pop`操作，以便只返回队列中等待时间最长的元素。

使用此队列实现的典型代码运行如下：

```py
queue = Queue() 
queue.enqueue(5) 
queue.enqueue(6) 
queue.enqueue(7) 
print(queue.inbound_stack) 
queue.dequeue() 
print(queue.inbound_stack) 
print(queue.outbound_stack) 
queue.dequeue() 
print(queue.outbound_stack) 
```

前述代码的输出如下：

```py
 [5, 6, 7] 
 [] 
 [7, 6] 
 [7] 
```

代码示例向队列添加元素，并打印队列中的元素。调用`dequeue`方法后，再次打印队列时观察到元素数量的变化。

使用两个堆栈实现队列是面试中经常提出的一个问题。

# 基于节点的队列

使用 Python 列表来实现队列是一个很好的起点，可以让我们感受队列的工作原理。我们完全可以利用指针结构的知识来实现自己的队列数据结构。

可以使用双向链表实现队列，对该数据结构的`插入`和`删除`操作的时间复杂度为**O**(*1*)。

`node`类的定义与我们在双向链表中定义的`Node`相同，如果双向链表能够实现 FIFO 类型的数据访问，那么它可以被视为队列，其中添加到列表中的第一个元素是第一个被移除的。

# 队列类

`queue`类与双向链表`list`类非常相似：

```py
class Queue: 
def __init__(self): 
        self.head = None 
        self.tail = None 
        self.count = 0 
```

在创建`queue`类的实例时，`self.head`和`self.tail`指针被设置为`None`。为了保持`Queue`中节点数量的计数，这里也维护了`count`实例变量，并将其设置为`0`。

# 入队操作

元素通过`enqueue`方法添加到`Queue`对象中。在这种情况下，元素是节点：

```py
    def enqueue(self, data): 
        new_node = Node(data, None, None) 
        if self.head is None: 
            self.head = new_node 
            self.tail = self.head 
        else: 
            new_node.prev = self.tail 
            self.tail.next = new_node 
            self.tail = new_node 

        self.count += 1 
```

`enqueue`方法的代码与双向链表的`append`操作中已经解释过的代码相同。它从传递给它的数据创建一个节点，并将其附加到队列的尾部，或者如果队列为空，则将`self.head`和`self.tail`都指向新创建的节点。队列中元素的总数增加了一行`self.count += 1`。

# 出队操作

使我们的双向链表作为队列的另一个操作是`dequeue`方法。这个方法是用来移除队列前面的节点。

要移除由`self.head`指向的第一个元素，使用`if`语句：

```py
def dequeue(self): 
current = self.head 
        if self.count == 1: 
            self.count -= 1 
            self.head = None 
            self.tail = None 
        elif self.count > 1: 
            self.head = self.head.next 
            self.head.prev = None 
            self.count -= 1 
```

`current`通过指向`self.head`来初始化。如果`self.count`为 1，则意味着列表中只有一个节点，也就是队列中只有一个节点。因此，要移除相关联的节点（由`self.head`指向），需要将`self.head`和`self.tail`变量设置为`None`。

另一方面，如果队列有许多节点，那么头指针将被移动以指向`self.head`的下一个节点。

在运行`if`语句之后，该方法返回被`head`指向的节点。`self.count`在`if`语句执行路径流程中的任何一种方式中都会减少一。

有了这些方法，我们成功地实现了一个队列，大量借鉴了双向链表的思想。

还要记住，将我们的双向链表转换为队列的唯一方法是两种方法，即`enqueue`和`dequeue`。

# 队列的应用

队列在计算机领域中用于实现各种功能。例如，网络上的每台计算机都不提供自己的打印机，可以通过排队来共享一个打印机。当打印机准备好打印时，它将选择队列中的一个项目（通常称为作业）进行打印。

操作系统还将进程排队以供 CPU 执行。让我们创建一个应用程序，利用队列来创建一个简单的媒体播放器。

# 媒体播放器队列

大多数音乐播放器软件允许用户将歌曲添加到播放列表中。点击播放按钮后，主播放列表中的所有歌曲都会依次播放。歌曲的顺序播放可以使用队列来实现，因为排队的第一首歌曲是首先播放的。这符合 FIFO 首字母缩写。我们将实现自己的播放列表队列，以 FIFO 方式播放歌曲。

基本上，我们的媒体播放器队列只允许添加曲目以及播放队列中的所有曲目。在一个完整的音乐播放器中，线程将被用来改进与队列的交互方式，同时音乐播放器继续用于选择下一首要播放、暂停或停止的歌曲。

`track`类将模拟音乐曲目：

```py
from random import randint 
class Track: 

    def __init__(self, title=None): 
        self.title = title 
        self.length = randint(5, 10) 
```

每个音轨都包含对歌曲标题的引用，以及歌曲的长度。长度是在 5 到 10 之间的随机数。随机模块提供了`randint`方法，使我们能够生成随机数。该类表示包含音乐的任何 MP3 音轨或文件。音轨的随机长度用于模拟播放歌曲或音轨所需的秒数。

要创建几个音轨并打印出它们的长度，我们需要做以下操作：

```py
track1 = Track("white whistle") 
track2 = Track("butter butter") 
print(track1.length) 
print(track2.length) 
```

上述代码的输出如下：

```py
    6
 7
```

由于为两个音轨生成的随机长度可能不同，因此您的输出可能会有所不同。

现在，让我们创建我们的队列。使用继承，我们只需从`queue`类继承：

```py
import time 
class MediaPlayerQueue(Queue): 

    def __init__(self): 
        super(MediaPlayerQueue, self).__init__() 
```

通过调用`super`来正确初始化队列。该类本质上是一个队列，其中包含队列中的多个音轨对象。要将音轨添加到队列中，需要创建一个`add_track`方法：

```py
    def add_track(self, track): 
        self.enqueue(track) 
```

该方法将`track`对象传递给队列`super`类的`enqueue`方法。这将实际上使用`track`对象（作为节点的数据）创建一个`Node`，并将尾部（如果队列不为空）或头部和尾部（如果队列为空）指向这个新节点。

假设队列中的音轨是按照先进先出的顺序播放的，那么`play`函数必须循环遍历队列中的元素：

```py
def play(self): 
        while self.count > 0: 
            current_track_node = self.dequeue() 
            print("Now playing {}".format(current_track_node.data.title)) 
            time.sleep(current_track_node.data.length) 
```

`self.count`用于计算音轨何时被添加到我们的队列以及何时被出队。如果队列不为空，对`dequeue`方法的调用将返回队列前面的节点（其中包含`track`对象）。然后，`print`语句通过节点的`data`属性访问音轨的标题。为了进一步模拟播放音轨，`time.sleep()`方法将暂停程序执行，直到音轨的秒数已经过去：

```py
time.sleep(current_track_node.data.length) 
```

媒体播放器队列由节点组成。当音轨被添加到队列时，该音轨会隐藏在一个新创建的节点中，并与节点的数据属性相关联。这就解释了为什么我们通过对`dequeue`的调用返回的节点的数据属性来访问节点的`track`对象：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/46c48a15-546f-44d7-b5d2-0a916532f052.jpg)

您可以看到，`node`对象不仅仅存储任何数据，而是在这种情况下存储音轨。

让我们来试试我们的音乐播放器：

```py
track1 = Track("white whistle") 
track2 = Track("butter butter") 
track3 = Track("Oh black star") 
track4 = Track("Watch that chicken") 
track5 = Track("Don't go") 
```

我们使用随机单词创建了五个音轨对象的标题：

```py
print(track1.length) 
print(track2.length) 
>> 8 >> 9
```

由于随机长度的原因，输出应该与您在您的机器上获得的结果不同。

接下来，创建`MediaPlayerQueue`类的一个实例：

```py
media_player = MediaPlayerQueue() 
```

音轨将被添加，并且`play`函数的输出应该按照我们排队的顺序打印出正在播放的音轨：

```py
media_player.add_track(track1) 
media_player.add_track(track2) 
media_player.add_track(track3) 
media_player.add_track(track4) 
media_player.add_track(track5) 
media_player.play() 
```

上述代码的输出如下：

```py
    >>Now playing white whistle
 >>Now playing butter butter
 >>Now playing Oh black star
 >>Now playing Watch that chicken
 >>Now playing Don't go
```

在程序执行时，可以看到音轨是按照它们排队的顺序播放的。在播放音轨时，系统还会暂停与音轨长度相等的秒数。

# 摘要

在本章中，我们利用了将节点链接在一起来创建其他数据结构的知识，即栈和队列。我们已经看到了这些数据结构如何紧密地模仿现实世界中的栈和队列。具体的实现，以及它们不同的类型，都已经展示出来。我们随后将栈和队列的概念应用于编写现实生活中的程序。

我们将在下一章中讨论树。将讨论树的主要操作，以及在哪些领域应用数据结构。


# 第九章：树

树是一种分层的数据结构。当我们处理列表、队列和栈时，项目是相互跟随的。但在树中，项目之间存在着*父子*关系。

为了形象化树的外观，想象一棵树从地面长出。现在把这个形象从你的脑海中移除。树通常是向下绘制的，所以你最好想象树的根结构向下生长。

在每棵树的顶部是所谓的*根节点*。这是树中所有其他节点的祖先。

树被用于许多事情，比如解析表达式和搜索。某些文档类型，如 XML 和 HTML，也可以以树形式表示。在本章中，我们将看一些树的用途。

在本章中，我们将涵盖以下领域：

+   树的术语和定义

+   二叉树和二叉搜索树

+   树的遍历

# 术语

让我们考虑一些与树相关的术语。

为了理解树，我们首先需要理解它们所依赖的基本思想。下图包含了一个典型的树，由字母 A 到 M 的字符节点组成。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ecea614b-c914-4a6d-a097-aa3b3f11da67.png)

以下是与树相关的术语列表：

+   **节点**：每个圈起来的字母代表一个节点。节点是任何包含数据的结构。

+   **根节点**：根节点是所有其他节点都来自的唯一节点。一个没有明显根节点的树不能被认为是一棵树。我们树中的根节点是节点 A。

+   **子树**：树的子树是一棵树，其节点是另一棵树的后代。节点 F、K 和 L 形成了原始树的子树，包括所有节点。

+   **度**：给定节点的子树数。只有一个节点的树的度为 0。这个单个树节点也被所有标准视为一棵树。节点 A 的度为 2。

+   **叶节点**：这是一个度为 0 的节点。节点 J、E、K、L、H、M 和 I 都是叶节点。

+   **边**：两个节点之间的连接。有时边可以将一个节点连接到自身，使边看起来像一个循环。

+   **父节点**：树中具有其他连接节点的节点是这些节点的父节点。节点 B 是节点 D、E 和 F 的父节点。

+   **子节点**：这是一个连接到其父节点的节点。节点 B 和 C 是节点 A 的子节点和根节点。

+   **兄弟节点**：所有具有相同父节点的节点都是兄弟节点。这使得节点 B 和 C 成为兄弟节点。

+   **级别**：节点的级别是从根节点到节点的连接数。根节点位于级别 0。节点 B 和 C 位于级别 1。

+   **树的高度**：这是树中的级别数。我们的树的高度为 4。

+   **深度**：节点的深度是从树的根到该节点的边数。节点 H 的深度为 2。

我们将从考虑树中的节点并抽象一个类开始对树的处理。

# 树节点

就像我们遇到的其他数据结构一样，如列表和栈，树是由节点构建而成的。但构成树的节点需要包含我们之前提到的关于父子关系的数据。

现在让我们看看如何在 Python 中构建一个二叉树`node`类：

```py
    class Node: 
        def __init__(self, data): 
            self.data = data 
            self.right_child = None 
            self.left_child = None 
```

就像我们以前的实现一样，一个节点是一个包含数据并持有对其他节点的引用的容器。作为二叉树节点，这些引用是指左右子节点。

为了测试这个类，我们首先创建了一些节点：

```py
    n1 = Node("root node")  
    n2 = Node("left child node") 
    n3 = Node("right child node") 
    n4 = Node("left grandchild node") 
```

接下来，我们将节点连接到彼此。我们让`n1`成为根节点，`n2`和`n3`成为它的子节点。最后，我们将`n4`作为`n2`的左子节点连接，这样当我们遍历左子树时，我们会得到一些迭代：

```py
    n1.left_child = n2 
    n1.right_child = n3 
    n2.left_child = n4 
```

一旦我们设置好了树的结构，我们就准备好遍历它了。如前所述，我们将遍历左子树。我们打印出节点并向下移动树到下一个左节点。我们一直这样做，直到我们到达左子树的末尾：

```py
    current = n1 
    while current: 
        print(current.data) 
        current = current.left_child 
```

正如你可能已经注意到的，这需要客户端代码中相当多的工作，因为你必须手动构建树结构。

# 二叉树

二叉树是每个节点最多有两个子节点的树。二叉树非常常见，我们将使用它们来构建 Python 中的 BST 实现。

以下图是一个以 5 为根节点的二叉树的示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/24dfae79-0a28-407a-af32-db8491f991a7.jpg)

每个子节点都被标识为其父节点的右子节点或左子节点。由于父节点本身也是一个节点，即使节点不存在，每个节点也会保存对右子节点和左子节点的引用。

常规二叉树没有关于如何排列树中元素的规则。它只满足每个节点最多有两个子节点的条件。

# 二叉搜索树

**二叉搜索树**（BST）是一种特殊类型的二叉树。也就是说，它在结构上是一棵二叉树。在功能上，它是一棵以一种能够高效搜索树的方式存储其节点的树。

BST 有一种结构。对于具有值的给定节点，左子树中的所有节点都小于或等于该节点的值。此外，该节点的右子树中的所有节点都大于父节点的值。例如，考虑以下树：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/c7916505-4ac0-48c2-af08-e7759443935c.png)

这是 BST 的一个示例。测试我们的树是否具有 BST 的属性，你会意识到根节点左子树中的所有节点的值都小于 5。同样，右子树中的所有节点的值都大于 5。这个属性适用于 BST 中的所有节点，没有例外：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/1d79ef04-0fb1-4ad6-ac1b-adcfbb3ab621.png)

尽管前面的图看起来与之前的图相似，但它并不符合 BST 的条件。节点 7 大于根节点 5；然而，它位于根节点的左侧。节点 4 位于其父节点 7 的右子树中，这是不正确的。

# 二叉搜索树实现

让我们开始实现 BST。我们希望树能够保存对其自己根节点的引用：

```py
    class Tree: 
        def __init__(self): 
            self.root_node = None 
```

这就是维护树状态所需的全部内容。让我们在下一节中检查树上的主要操作。

# 二叉搜索树操作

基本上有两个操作对于使用 BST 是必要的。这些是“插入”和“删除”操作。这些操作必须遵循一个规则，即它们必须保持给 BST 赋予结构的原则。

在我们处理节点的插入和删除之前，让我们讨论一些同样重要的操作，这些操作将帮助我们更好地理解“插入”和“删除”操作。

# 查找最小和最大节点

BST 的结构使得查找具有最大和最小值的节点非常容易。

要找到具有最小值的节点，我们从树的根开始遍历，并在到达子树时每次访问左节点。我们做相反的操作来找到树中具有最大值的节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/c229180d-2172-4729-bdfb-c90772604353.png)

我们从节点 6 到 3 到 1 向下移动，以找到具有最小值的节点。同样，我们向下移动 6、8 到节点 10，这是具有最大值的节点。

查找最小和最大节点的相同方法也适用于子树。具有根节点 8 的子树中的最小节点是 7。该子树中具有最大值的节点是 10。

返回最小节点的方法如下：

```py
    def find_min(self): 
        current = self.root_node 
        while current.left_child: 
            current = current.left_child 

        return current 
```

`while`循环继续获取左节点并访问它，直到最后一个左节点指向`None`。这是一个非常简单的方法。返回最大节点的方法相反，其中`current.left_child`现在变为`current.right_child`。

在 BST 中查找最小值或最大值需要**O**(*h*)，其中*h*是树的高度。

# 插入节点

BST 的操作之一是需要将数据插入为节点。在我们的第一个实现中，我们必须自己插入节点，但在这里，我们将让树负责存储其数据。

为了使搜索成为可能，节点必须以特定的方式存储。对于每个给定的节点，其左子节点将保存小于其自身值的数据，如前所述。该节点的右子节点将保存大于其父节点的数据。

我们将通过使用数据 5 来创建一个新的整数 BST。为此，我们将创建一个数据属性设置为 5 的节点。

现在，要添加值为 3 的第二个节点，3 与根节点 5 进行比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/d212c46e-6046-4151-bb46-cf1ed26e4051.jpg)

由于 5 大于 3，它将放在节点 5 的左子树中。我们的 BST 将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/0e1ead82-8fb4-4ae6-a8de-d0b1578f7bf9.jpg)

树满足 BST 规则，左子树中的所有节点都小于其父节点。

要向树中添加值为 7 的另一个节点，我们从值为 5 的根节点开始比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/b0225066-e12d-48d9-8d42-cd8da6f62f91.jpg)

由于 7 大于 5，值为 7 的节点位于此根节点的右侧。

当我们想要添加一个等于现有节点的节点时会发生什么？我们将简单地将其添加为左节点，并在整个结构中保持此规则。

如果一个节点已经有一个子节点在新节点应该放置的位置，那么我们必须沿着树向下移动并将其附加。

让我们添加另一个值为 1 的节点。从树的根开始，我们比较 1 和 5：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/13de8d9e-97ba-4834-9756-cf31e34a95eb.jpg)

比较表明 1 小于 5，因此我们将注意力转向 5 的左节点，即值为 3 的节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/3621290e-d166-4e10-9c5f-824992152daa.png)

我们将 1 与 3 进行比较，由于 1 小于 3，我们向下移动到节点 3 的下一级并向左移动。但那里没有节点。因此，我们创建一个值为 1 的节点，并将其与节点 3 的左指针关联，以获得以下结构：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/e9c6c705-4546-4627-9866-f3c30baf1fae.jpg)

到目前为止，我们只处理包含整数或数字的节点。对于数字，大于和小于的概念是清晰定义的。字符串将按字母顺序比较，因此在那里也没有太大的问题。但是，如果您想在 BST 中存储自定义数据类型，您必须确保您的类支持排序。

现在让我们创建一个函数，使我们能够将数据作为节点添加到 BST 中。我们从函数声明开始：

```py
    def insert(self, data): 
```

到现在为止，你已经习惯了我们将数据封装在节点中的事实。这样，我们将`node`类隐藏在客户端代码中，客户端代码只需要处理树：

```py
        node = Node(data) 
```

首先检查是否有根节点。如果没有，新节点将成为根节点（我们不能没有根节点的树）：

```py
        if self.root_node is None: 
            self.root_node = node 
        else: 
```

当我们沿着树走时，我们需要跟踪我们正在处理的当前节点以及其父节点。变量`current`始终用于此目的：

```py
        current = self.root_node 
        parent = None 
        while True: 
            parent = current 
```

在这里，我们必须进行比较。如果新节点中保存的数据小于当前节点中保存的数据，则我们检查当前节点是否有左子节点。如果没有，这就是我们插入新节点的地方。否则，我们继续遍历：

```py
        if node.data < current.data: 
            current = current.left_child 
            if current is None: 
                parent.left_child = node 
                return 
```

现在我们处理大于或等于的情况。如果当前节点没有右子节点，则新节点将插入为右子节点。否则，我们继续向下移动并继续寻找插入点：

```py
        else: 
            current = current.right_child 
            if current is None: 
                parent.right_child = node 
                return 
```

在 BST 中插入一个节点需要**O**(*h*)，其中*h*是树的高度。

# 删除节点

BST 上的另一个重要操作是节点的`删除`或`移除`。在此过程中，我们需要考虑三种情况。我们要删除的节点可能有以下情况：

+   没有子节点

+   一个子节点

+   两个子节点

第一种情况是最容易处理的。如果要删除的节点没有子节点，我们只需将其与其父节点分离：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/226a56a7-c9ba-47f9-b04b-e7cd9aff5349.png)

因为节点 A 没有子节点，所以我们只需将其与其父节点节点 Z 分离。

另一方面，当我们想要删除的节点有一个子节点时，该节点的父节点将指向该特定节点的子节点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/b0c13358-279e-485a-8d1f-1ea43fe7e18e.png)

为了删除只有一个子节点节点 5 的节点 6，我们将节点 9 的左指针指向节点 5。父节点和子节点之间的关系必须得到保留。这就是为什么我们需要注意子节点如何连接到其父节点（即要删除的节点）。存储要删除节点的子节点。然后我们将要删除节点的父节点连接到该子节点。

当我们想要删除的节点有两个子节点时，会出现一个更复杂的情况：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/42141387-d400-4f4b-8ea8-774c2df6d9f0.png)

我们不能简单地用节点 6 或 13 替换节点 9。我们需要找到节点 9 的下一个最大后代。这是节点 12。要到达节点 12，我们移动到节点 9 的右节点。然后向左移动以找到最左节点。节点 12 被称为节点 9 的中序后继。第二步类似于查找子树中的最大节点。

我们用节点 9 的值替换节点 9 的值，并删除节点 12。删除节点 12 后，我们得到了一个更简单的节点删除形式，这已经在之前进行过处理。节点 12 没有子节点，因此我们相应地应用删除没有子节点的节点的规则。

我们的`node`类没有父引用。因此，我们需要使用一个辅助方法来搜索并返回具有其父节点的节点。该方法类似于`search`方法：

```py
    def get_node_with_parent(self, data): 
        parent = None 
        current = self.root_node 
        if current is None: 
            return (parent, None) 
        while True: 
            if current.data == data: 
                return (parent, current) 
            elif current.data > data: 
                parent = current 
                current = current.left_child 
            else: 
                parent = current 
                current = current.right_child 

        return (parent, current) 
```

唯一的区别是，在我们更新循环内的当前变量之前，我们使用`parent = current`存储其父级。执行实际删除节点的方法始于这个搜索：

```py
    def remove(self, data): 
        parent, node = self.get_node_with_parent(data) 

        if parent is None and node is None: 
            return False 

        # Get children count 
        children_count = 0 

        if node.left_child and node.right_child: 
            children_count = 2 
        elif (node.left_child is None) and (node.right_child is None): 
            children_count = 0 
        else: 
            children_count = 1 
```

我们将父节点和找到的节点传递给`parent`和`node`，代码为`parent, node = self.get_node_with_parent(data)`。了解要删除的节点有多少子节点是有帮助的。这就是`if`语句的目的。

之后，我们需要开始处理节点可以被删除的各种条件。`if`语句的第一部分处理节点没有子节点的情况：

```py
        if children_count == 0: 
            if parent: 
                if parent.right_child is node: 
                    parent.right_child = None 
                else: 
                    parent.left_child = None 
            else: 
                self.root_node = None 
```

`if parent:` 用于处理只有一个节点的 BST 的情况。

在要删除的节点只有一个子节点的情况下，`if`语句的`elif`部分执行以下操作：

```py
        elif children_count == 1: 
            next_node = None 
            if node.left_child: 
                next_node = node.left_child 
            else: 
                next_node = node.right_child 

            if parent: 
                if parent.left_child is node: 
                    parent.left_child = next_node 
                else: 
                    parent.right_child = next_node 
            else: 
                self.root_node = next_node 
```

`next_node`用于跟踪节点指向的单个节点的位置。然后我们将`parent.left_child`或`parent.right_child`连接到`next_node`。

最后，我们处理了要删除的节点有两个子节点的情况：

```py
        ... 
        else: 
            parent_of_leftmost_node = node 
            leftmost_node = node.right_child 
            while leftmost_node.left_child: 
                parent_of_leftmost_node = leftmost_node 
                leftmost_node = leftmost_node.left_child 

            node.data = leftmost_node.data 
```

在查找中序后继时，我们使用`leftmost_node = node.right_child`移动到右节点。只要存在左节点，`leftmost_node.left_child`将计算为`True`，`while`循环将运行。当我们到达最左节点时，它要么是叶节点（意味着它没有子节点），要么有一个右子节点。

我们使用`node.data = leftmost_node.data`更新即将被移除的节点的值：

```py
    if parent_of_leftmost_node.left_child == leftmost_node: 
       parent_of_leftmost_node.left_child = leftmost_node.right_child 
    else: 
       parent_of_leftmost_node.right_child = leftmost_node.right_child 
```

前面的陈述使我们能够正确地将最左节点的父节点与任何子节点正确连接。请注意等号右侧保持不变。这是因为中序后继只能有一个右子节点作为其唯一子节点。

`remove`操作的时间复杂度为**O**(*h*),其中*h*是树的高度。

# 搜索树

由于`insert`方法以特定方式组织数据，我们将遵循相同的过程来查找数据。在这个实现中，如果找到了数据，我们将简单地返回数据，如果没有找到数据，则返回`None`：

```py
    def search(self, data): 
```

我们需要从最顶部开始搜索，也就是从根节点开始：

```py
        current = self.root_node 
        while True: 
```

我们可能已经经过了一个叶节点，这种情况下数据不存在于树中，我们将返回`None`给客户端代码：

```py
            if current is None: 
                return None 
```

我们也可能已经找到了数据，这种情况下我们会返回它：

```py
            elif current.data is data: 
                return data 
```

根据 BST 中数据存储的规则，如果我们正在搜索的数据小于当前节点的数据，我们需要向树的左侧移动：

```py
            elif current.data > data: 
                current = current.left_child 
```

现在我们只剩下一个选择：我们正在寻找的数据大于当前节点中保存的数据，这意味着我们需要向树的右侧移动：

```py
            else: 
                current = current.right_child 
```

最后，我们可以编写一些客户端代码来测试 BST 的工作原理。我们创建一棵树，并在 1 到 10 之间插入一些数字。然后我们搜索该范围内的所有数字。存在于树中的数字将被打印出来：

```py
    tree = Tree() 
    tree.insert(5) 
    tree.insert(2) 
    tree.insert(7) 
    tree.insert(9) 
    tree.insert(1) 

    for i in range(1, 10): 
        found = tree.search(i) 
        print("{}: {}".format(i, found)) 
```

# 树的遍历

访问树中的所有节点可以通过深度优先或广度优先完成。这种遍历方式不仅适用于二叉搜索树，而是适用于树的一般情况。

# 深度优先遍历

在这种遍历方式中，我们会在向上继续遍历之前，沿着一个分支（或边）到达其极限。我们将使用递归方法进行遍历。深度优先遍历有三种形式，即`中序`、`前序`和`后序`。

# 中序遍历和中缀表示法

我们大多数人可能习惯用这种方式表示算术表达式，因为这是我们通常在学校里学到的方式。操作符被插入（中缀）在操作数之间，如`3 + 4`。必要时，可以使用括号来构建更复杂的表达式：`(4 + 5) * (5 - 3)`。

在这种遍历方式中，您将访问左子树、父节点，最后是右子树。

返回树中节点的中序列表的递归函数如下：

```py
    def inorder(self, root_node): 
        current = root_node 
        if current is None: 
            return 
        self.inorder(current.left_child) 
        print(current.data) 
        self.inorder(current.right_child) 
```

我们通过打印节点并使用`current.left_child`和`current.right_child`进行两次递归调用来访问节点。

# 前序遍历和前缀表示法

前缀表示法通常被称为波兰表示法。在这里，操作符在其操作数之前，如`+ 3 4`。由于没有优先级的歧义，因此不需要括号：`* + 4 5 - 5 3`。

要以前序方式遍历树，您将按照节点、左子树和右子树节点的顺序访问。

前缀表示法是 LISP 程序员所熟知的。

用于此遍历的递归函数如下：

```py
    def preorder(self, root_node): 
        current = root_node 
        if current is None: 
            return 
        print(current.data) 
        self.preorder(current.left_child) 
        self.preorder(current.right_child) 
```

注意递归调用的顺序。

# 后序遍历和后缀表示法。

后缀或**逆波兰表示法**（**RPN**）将操作符放在其操作数之后，如`3 4 +`。与波兰表示法一样，操作符的优先级永远不会引起混淆，因此不需要括号：`4 5 + 5 3 - *`。

在这种遍历方式中，您将访问左子树、右子树，最后是根节点。

`后序遍历`方法如下：

```py
    def postorder(self, root_node): 
        current = root_node 
        if current is None: 
            return 
        self.postorder(current.left_child) 
        self.postorder(current.right_child) 

        print(current.data)
```

# 广度优先遍历

这种遍历方式从树的根开始，并从树的一个级别访问节点到另一个级别：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/798e2ee2-65c7-4c0a-bfea-165a880ed447.png)

第 1 级的节点是节点 4。我们通过打印其值来访问此节点。接下来，我们移动到第 2 级并访问该级别上的节点，即节点 2 和 8。在最后一级，第 3 级，我们访问节点 1、3、5 和 10。

这种遍历的完整输出是 4、2、8、1、3、5 和 10。

这种遍历模式是通过使用队列数据结构实现的。从根节点开始，我们将其推入队列。队列前端的节点被访问（出队），然后打印并存储以备后用。左节点被添加到队列中，然后是右节点。由于队列不为空，我们重复这个过程。

算法的干运行将根节点 4 入队，出队并访问节点。节点 2 和 8 被入队，因为它们分别是左节点和右节点。节点 2 被出队以进行访问。它的左节点和右节点，即 1 和 3，被入队。此时，队列前端的节点是 8。我们出队并访问节点 8，之后我们入队其左节点和右节点。因此，这个过程一直持续，直到队列为空。

算法如下：

```py
    from collections import deque 
    class Tree: 
        def breadth_first_traversal(self): 
            list_of_nodes = [] 
            traversal_queue = deque([self.root_node]) 
```

我们将根节点入队，并在`list_of_nodes`列表中保留一个访问过的节点列表。`dequeue`类用于维护队列：

```py
        while len(traversal_queue) > 0: 
            node = traversal_queue.popleft() 
            list_of_nodes.append(node.data) 
```

```py
            if node.left_child: 
                traversal_queue.append(node.left_child) 

            if node.right_child: 
                traversal_queue.append(node.right_child) 
        return list_of_nodes 
```

如果`traversal_queue`中的元素数量大于零，则执行循环体。队列前端的节点被弹出并附加到`list_of_nodes`列表。第一个`if`语句将`node`的左子节点入队，如果存在左节点。第二个`if`语句对右子节点执行相同的操作。

`list_of_nodes`在最后一个语句中返回。

# 二叉搜索树的好处

我们现在简要地看一下，为什么使用 BST 比使用列表进行搜索更好。假设我们有以下数据集：5、3、7、1、4、6 和 9。使用列表，最坏的情况需要在找到搜索项之前搜索整个包含七个元素的列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/720691f5-6681-473f-a80c-1f1cdba24822.jpg)

搜索`9`需要六次跳跃。

使用树，最坏的情况是三次比较：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/ace39d6e-f99f-432c-96fa-258b74bd400c.jpg)

搜索`9`需要两步。

然而请注意，如果你按照 1、2、3、5、6、7、9 的顺序将元素插入树中，那么这棵树将不会比列表更有效。我们需要首先平衡树：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/260a95e2-481f-4441-b0dc-991d1aafed8b.jpg)

因此，重要的不仅是使用 BST，而且选择自平衡树有助于改进`search`操作。

# 表达式树

树结构也用于解析算术和布尔表达式。例如，`3 + 4`的表达式树如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/d3bff613-f1df-495f-8f23-3b101b9b8633.jpg)

对于稍微复杂的表达式`(4 + 5) * (5-3)`，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py/img/bf51f42d-d166-483b-93ff-0c22004c45da.jpg)

# 解析逆波兰表达式

现在我们将为后缀表示法中的表达式构建一棵树。然后我们将计算结果。我们将使用一个简单的树实现。为了保持简单，因为我们将通过合并较小的树来增长树，我们只需要一个树节点实现：

```py
    class TreeNode: 
        def __init__(self, data=None): 
            self.data = data 
            self.right = None 
            self.left = None 
```

为了构建树，我们将寻求栈的帮助。很快你就会明白为什么。但目前，让我们创建一个算术表达式并设置我们的栈：

```py
        expr = "4 5 + 5 3 - *".split() 
        stack = Stack() 
```

由于 Python 是一种试图具有合理默认值的语言，它的`split()`方法默认情况下会在空格上拆分。（如果你仔细想想，这很可能也是你期望的。）结果将是`expr`是一个包含值 4、5、+、5、3、-和*的列表。

expr 列表的每个元素都可能是操作符或操作数。如果我们得到一个操作数，那么我们将其嵌入到一个树节点中并将其推入堆栈。另一方面，如果我们得到一个操作符，那么我们将操作符嵌入到一个树节点中，并将其两个操作数弹出到节点的左右子节点中。在这里，我们必须小心确保第一个弹出的操作数进入右子节点，否则我们将在减法和除法中出现问题。

以下是构建树的代码：

```py
    for term in expr: 
        if term in "+-*/": 
            node = TreeNode(term) 
            node.right = stack.pop() 
            node.left = stack.pop() 
        else: 
            node = TreeNode(int(term)) 
        stack.push(node) 
```

请注意，在操作数的情况下，我们执行了从字符串到整数的转换。如果需要支持浮点数操作数，可以使用`float()`。

在这个操作结束时，我们应该在堆栈中只有一个元素，它包含了完整的树。

现在我们可能想要评估表达式。我们构建了以下小函数来帮助我们：

```py
    def calc(node): 
        if node.data is "+": 
            return calc(node.left) + calc(node.right) 
        elif node.data is "-": 
            return calc(node.left) - calc(node.right) 
        elif node.data is "*": 
            return calc(node.left) * calc(node.right) 
        elif node.data is "/": 
            return calc(node.left) / calc(node.right) 
        else: 
            return node.data 
```

这个函数非常简单。我们传入一个节点。如果节点包含一个操作数，那么我们就简单地返回该值。然而，如果我们得到一个操作符，那么我们就对节点的两个子节点执行操作符代表的操作。然而，由于一个或多个子节点也可能包含操作符或操作数，我们在两个子节点上递归调用`calc()`函数（要记住每个节点的所有子节点也都是节点）。

现在我们只需要从堆栈中弹出根节点并将其传递给`calc()`函数，我们就应该得到计算的结果：

```py
    root = stack.pop() 
    result = calc(root) 
    print(result) 
```

运行这个程序应该得到结果 18，这是`(4 + 5) * (5 - 3)`的结果。

# 平衡树

之前我们提到，如果节点按顺序插入树中，那么树的行为就更像是一个列表，也就是说，每个节点恰好有一个子节点。我们通常希望尽量减少树的高度，填满树中的每一行。这个过程称为平衡树。

有许多类型的自平衡树，例如红黑树、AA 树和替罪羊树。这些树在修改树的每个操作（如插入或删除）期间平衡树。

还有一些外部算法可以平衡树。这样做的好处是你不需要在每次操作时都平衡树，而是可以在需要时才进行平衡。

# 堆

在这一点上，我们简要介绍堆数据结构。堆是树的一种特殊形式，其中节点以特定的方式排序。堆分为最大堆和最小堆。在最大堆中，每个父节点必须始终大于或等于其子节点。因此，根节点必须是树中最大的值。最小堆则相反。每个父节点必须小于或等于其两个子节点。因此，根节点保存最小的值。

堆用于许多不同的事情。首先，它们用于实现优先队列。还有一种非常高效的排序算法，称为堆排序，使用了堆。我们将在后续章节中深入研究这些内容。

# 总结

在本章中，我们看了树结构和它们的一些示例用途。我们特别研究了二叉树，这是树的一个子类型，其中每个节点最多有两个子节点。

我们看到了二叉树如何作为可搜索的数据结构与 BST 一起使用。我们发现，在大多数情况下，在 BST 中查找数据比在链表中更快，尽管如果数据按顺序插入，情况就不同了，除非树是平衡的。

广度优先和深度优先搜索遍历模式也使用队列递归实现了。

我们还看了二叉树如何用来表示算术或布尔表达式。我们构建了一个表达式树来表示算术表达式。我们展示了如何使用栈来解析以逆波兰表示法编写的表达式，构建表达式树，最后遍历它以获得算术表达式的结果。

最后，我们提到了堆，这是树结构的一种特殊形式。在本章中，我们试图至少奠定堆的理论基础，以便在接下来的章节中为不同的目的实现堆。
