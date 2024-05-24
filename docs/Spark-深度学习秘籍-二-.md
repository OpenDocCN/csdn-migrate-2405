# Spark 深度学习秘籍（二）

> 原文：[`zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB`](https://zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：循环神经网络的痛点

在本章中，我们将涵盖以下内容：

+   前馈网络简介

+   RNN 的顺序工作

+   痛点＃1 - 梯度消失问题

+   痛点＃2 - 梯度爆炸问题

+   LSTM 的顺序工作

# 介绍

循环神经网络已被证明在涉及学习和预测序列数据的任务中非常高效。然而，当涉及自然语言时，长期依赖性的问题就出现了，这基本上是记住特定对话、段落或句子的上下文，以便在未来做出更好的预测。例如，考虑一个句子，说：

*去年，我碰巧访问了中国。中国的食物不仅与世界上其他地方提供的中国食物不同，而且人们也非常热情好客。在这个美丽的国家呆了三年，我学会了说一口很好的......*

如果将前面的句子输入到循环神经网络中以预测句子中的下一个单词（比如中国），网络会发现很难，因为它没有句子上下文的记忆。这就是我们所说的长期依赖性。为了正确预测单词“中国”，网络需要知道句子的上下文，还需要记住我碰巧去年访问中国的事实。因此，循环神经网络在执行此类任务时效率低下。然而，**长短期记忆单元**（**LSTM**）可以克服这个问题，它能够记住长期依赖性并将信息存储在细胞状态中。稍后将讨论 LSTM，但本章的大部分内容将重点介绍神经网络、激活函数、循环网络、循环网络的一些主要痛点或缺点，以及如何通过使用 LSTM 来克服这些缺点。

# 前馈网络简介

要理解循环网络，首先必须了解前馈网络的基础知识。这两种网络都是根据它们通过网络节点执行的一系列数学运算的方式命名的。一种只通过每个节点向一个方向传递信息（永远不会两次触及给定节点），而另一种则通过循环将信息传递并将其反馈到同一节点（有点像反馈循环）。很容易理解第一种称为**前馈网络**，而后者是循环的。

# 准备就绪

理解任何神经网络图表的最重要概念是计算图的概念。计算图实际上就是相互连接的神经网络节点，每个节点执行特定的数学函数。

# 操作步骤...

前馈神经网络通过一组计算节点（即数学运算符和激活函数）将输入（到输入层）传递到计算网络输出的层。输出层是神经网络的最终层，通常包含线性函数。输入层和输出层之间的层称为**隐藏层**，通常包含非线性元素或函数：

1.  下图（a）显示了前馈神经网络中节点如何相互连接：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00095.jpeg)

前馈神经网络

1.  前馈神经网络主要通过隐藏层节点中使用的函数（激活函数）的类型来区分彼此。它们还通过在训练期间用于优化网络的其他参数的算法来区分彼此。

1.  在前面的图中显示的节点之间的关系不需要对每个节点进行完全填充；优化策略通常从大量的隐藏节点开始，并通过消除连接和可能的节点来调整网络，随着训练的进行。在训练过程中可能不需要利用每个节点。

# 工作原理...

神经元是任何神经网络的基本结构元素。神经元可以被看作是一个简单的数学函数或运算符，它对通过它流动的输入进行操作，以产生从它流出的输出。神经元的输入与节点的权重矩阵相乘，对所有输入求和，进行平移，并通过激活函数传递。这基本上是数学中的矩阵运算，如下所述：

1.  神经元的计算图表示如前图(b)所示。

1.  单个神经元或节点的传递函数如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00096.jpeg)

这里，*x*[ *i* ]是第 i 个节点的输入，*w*[ *i* ]是与第 i 个节点相关的权重项，*b*是通常添加的偏差，以防止过拟合，*f*(⋅)是作用于流入节点的输入的激活函数，*y*是节点的输出。

1.  具有 S 形激活函数的神经元通常用于神经网络的隐藏层，并且恒等函数通常用于输出层。

1.  激活函数通常被选择为确保节点的输出严格增加、平滑（连续的一阶导数）或渐近的方式。

1.  以下的逻辑函数被用作 S 形激活函数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00097.jpeg)

1.  使用反向传播算法训练的神经元，如果激活函数是反对称的，即*f*(-*x*) = -*f*(*x*)，可能会学习得更快，就像 S 形激活函数的情况一样。反向传播算法将在本章的后续部分中详细讨论。

1.  逻辑函数不是反对称的，但可以通过简单的缩放和移位来使其成为反对称，从而得到具有由*f*(*x*) = 1 - *f*²(*x*)描述的一阶导数的双曲正切函数，如下数学函数所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00098.jpeg)

1.  S 形函数及其导数的简单形式允许快速准确地计算梯度，以优化权重和偏差的选择，并进行二阶误差分析。

# 还有更多...

在神经网络的各层中的每个神经元/节点上执行一系列矩阵运算。下图以更数学化的方式展示了前馈网络，这将帮助您更好地理解每个节点/神经元的操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00099.jpeg)

1.  直观地，我们可以看到输入（向量或矩阵）首先被权重矩阵相乘。然后添加一个偏差项，然后使用激活函数（如 ReLU、tanh、sigmoid、阈值等）激活以产生输出。激活函数是确保网络能够学习线性和非线性函数的关键。 

1.  然后，这个输出作为下一个神经元的输入，然后再次执行相同的一系列操作。许多这样的神经元组合在一起形成一个层（执行输入向量的某个功能或学习某个特征），许多这样的层组合在一起形成一个前馈神经网络，可以完全学会识别输入，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00100.gif)

1.  假设我们的前馈网络已经训练好，可以对狗和猫的图像进行分类。一旦网络训练好，如下图所示，它将学会在呈现新图像时将图像标记为狗或猫：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00101.jpeg)

1.  在这样的网络中，当前输出与先前或未来的输出之间没有关系。

1.  这意味着前馈网络基本上可以暴露给任何随机的图像集合，它暴露给的第一张图像不一定会改变它对第二张或第三张图像的分类方式。因此，我们可以说在时间步*t*的输出与时间步*t-1*的输出是独立的。

1.  前馈网络在图像分类等情况下效果很好，其中数据不是顺序的。前馈网络在使用两个相关变量时也表现良好，比如温度和位置、身高和体重、汽车速度和品牌等。

1.  然而，可能存在当前输出依赖于先前时间步的输出的情况（数据的顺序很重要）。

1.  考虑阅读一本书的情景。你对书中句子的理解基于你对句子中所有单词的理解。使用前馈网络来预测句子中的下一个单词是不可能的，因为在这种情况下输出取决于先前的输出。

1.  同样，有许多情况下，输出需要先前的输出或一些先前输出的信息（例如，股市数据、自然语言处理、语音识别等）。前馈网络可以被修改如下图所示，以捕获先前输出的信息：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00102.jpeg)

1.  在时间步*t*，输入*t*以及*t-1*的信息都提供给网络，以获得时间*t*的输出。

1.  同样，从时间步*t*以及新输入都被输入到网络中的时间步*t+1*，以产生*t+1*的输出。前面图表的右侧是表示这样一个网络的一般方式，其中网络的输出会作为未来时间步的输入。这样的网络被称为**循环神经网络**（**RNN**）。

# 另请参见

**激活函数**：在人工神经网络中，节点的激活函数决定了节点在给定输入或一组输入时产生的输出类型。输出*y[k]*由输入*u[k]*和偏置*b[k]*通过激活函数*φ(.)*得到，如下式所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00103.jpeg)

有各种类型的激活函数。以下是常用的几种：

1.  **阈值函数**：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00104.gif)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00105.jpeg)

从前面的图表可以清楚地看出，这种函数限制了神经元的输出值在 0 和 1 之间。在许多情况下，这可能是有用的。然而，这个函数是不可微的，这意味着它不能用于学习非线性，而在使用反向传播算法时，这是至关重要的。

1.  **Sigmoid 函数**：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00106.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00107.jpeg)

Sigmoid 函数是一个具有下限为 0 和上限为 1 的逻辑函数，与阈值函数一样。这个激活函数是连续的，因此也是可微的。在 Sigmoid 函数中，前面函数的斜率参数由α给出。这个函数是非线性的，这对于提高性能至关重要，因为它能够容纳输入数据中的非线性，而常规线性函数不能。具有非线性能力确保权重和偏置的微小变化会导致神经元输出的显著变化。

1.  **双曲正切函数（tanh）**：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00108.jpeg)

这个函数使激活函数的范围从 0 到 1 变为-1 到+1。

1.  **修正线性单元（ReLU）函数**：ReLU 是许多逻辑单元的平滑近似，产生稀疏的活动向量。以下是该函数的方程：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00109.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00110.jpeg)

ReLU 函数图

在前面的图表中，softplus ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00111.jpeg)(x) = log ( 1 + e^x)是整流器的平滑近似。

1.  **Maxout 函数**：该函数利用一种称为**“dropout”**的技术，并改进了快速近似模型平均的准确性，以便促进优化。

Maxout 网络不仅学习隐藏单元之间的关系，还学习每个隐藏单元的激活函数。通过主动丢弃隐藏单元，网络被迫在训练过程中找到其他路径以从给定输入到输出。以下图表是这个过程如何工作的图形描述：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00112.jpeg)

Maxout 网络

前面的图表显示了具有五个可见单元、三个隐藏单元和每个隐藏单元两个神经元的 Maxout 网络。Maxout 函数由以下方程给出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00113.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00114.jpeg)

这里 W..[ij ]是通过访问矩阵 W ∈  ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00115.jpeg)的第二坐标 *i* 和第三坐标 *j*获得的输入的大小的均值向量。中间单元的数量（*k）*称为 Maxout 网络使用的片数。以下图表显示了 Maxout 函数与 ReLU 和**参数修正线性单元**（**PReLU**）函数的比较：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00116.jpeg)

Maxout、ReLU 和 PReLU 函数的图形比较

# RNN 的顺序工作

递归神经网络是一种人工神经网络，旨在识别和学习数据序列中的模式。此类序列数据的一些示例包括：

+   手写

+   诸如客户评论、书籍、源代码等文本

+   口语/自然语言

+   数值时间序列/传感器数据

+   股价变动数据

# 准备工作

在递归神经网络中，来自上一个时间步的隐藏状态被反馈到下一个时间步的网络中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00117.jpeg)

基本上，进入网络的朝上箭头代表 RNN 在每个时间步的输入（矩阵/向量），而从网络中出来的朝上箭头代表每个 RNN 单元的输出。水平箭头表示在特定时间步（由特定神经元）学习的信息传递到下一个时间步。

有关使用 RNN 的更多信息，请访问：

[`deeplearning4j.org/usingrnns`](https://deeplearning4j.org/usingrnns)

# 如何做…

在递归网络的每个节点/神经元上，进行一系列矩阵乘法步骤。首先将输入向量/矩阵乘以权重向量/矩阵，然后添加偏差项，最后通过激活函数产生输出（就像前馈网络的情况一样）：

1.  以下图表显示了一种直观和数学化的方式来可视化 RNNs，以计算图的形式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00118.jpeg)

1.  在第一个时间步骤（即*t=0*），使用前面图表右侧的第一个公式计算*h*[*0*]。由于*h*^(*-1*)不存在，中间项变为零。

1.  输入矩阵*x*[*0*]乘以权重矩阵*w[i]*，并且将偏差*b[h]*添加到这个项。

1.  然后将前面的两个矩阵相加，然后通过激活函数*g[h]*获得*h[0]*。

1.  同样，*y[0]*使用前面图表右侧的第二个方程计算，方法是将*h[0]*与权重矩阵*w[y]*相乘，加上偏差*b[y]*，并通过激活函数*g[y]*传递。

1.  在下一个时间步（即*t=1*），*h^((t-1))*存在。它就是*h[0]*。这个项乘以权重矩阵*w[R]*，也作为网络的输入与新的输入矩阵*x[1]*一起提供。

1.  这个过程在多个时间步骤中重复进行，权重、矩阵和偏差在不同的时间步骤中通过整个网络流动。

1.  整个过程在一个迭代中执行，这构成了网络的前向传递。

# 它是如何工作的...

训练前馈神经网络最常用的技术是通过时间的反向传播。这是一种监督学习方法，用于通过在每个时间步之后更新网络中的权重和偏差来减少损失函数。执行多个训练周期（也称为时代），其中由损失函数确定的误差通过梯度下降的技术进行反向传播。在每个训练周期结束时，网络更新其权重和偏差，以产生接近期望输出的输出，直到达到足够小的误差：

1.  在每次迭代期间，反向传播算法基本上实现以下三个基本步骤：

+   输入数据的前向传递和计算损失函数

+   梯度和误差的计算

+   通过时间的反向传播和相应地调整权重和偏差

1.  在通过激活函数加上偏差后的输入的加权和被馈送到网络中并获得输出后，网络立即比较预测输出与实际情况（正确输出）的差异有多大。

1.  接下来，网络计算误差。这实际上就是网络输出减去实际/正确的输出。

1.  下一步涉及根据计算的误差在整个网络中进行反向传播。然后更新权重和偏差以观察误差是增加还是减少。

1.  网络还记得，增加权重和偏差会增加误差，或者减少权重和偏差会减少误差。

1.  根据前述推论，网络在每次迭代期间继续以使误差最小的方式更新权重和偏差。下面的例子将使事情更清楚。

1.  考虑一个简单的情况，教会机器如何将一个数字加倍，如下表所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00119.jpeg)

1.  正如你所看到的，通过随机初始化权重（*W = 3*），我们得到了 0、3、6 和 9 的输出。

1.  误差是通过将正确输出的列减去模型输出的列来计算的。平方误差实际上就是每个误差项与自身相乘。通常最好使用平方误差，因为它消除了误差项中的负值。

1.  模型随后意识到，为了最小化误差，需要更新权重。

1.  假设在下一次迭代中，模型将其权重更新为*W = 4*。这将导致以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00120.jpeg)

1.  模型现在意识到，通过增加权重到*W = 4*，实际上误差增加了。因此，在下一次迭代中，模型通过将权重减小到*W = 2*来更新权重，从而得到实际/正确的输出。

1.  请注意，在这个简单的情况下，当增加权重时，误差增加，当减少权重时，误差减少，如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00121.jpeg)

1.  在实际的神经网络中，每次迭代期间都会执行多次这样的权重更新，直到模型收敛到实际/正确的输出。

# 还有更多...

如前面的情况所示，当增加权重时，误差增加，但当减少权重时，误差减少。但这并不总是成立。网络使用以下图表来确定如何更新权重以及何时停止更新它们：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00122.jpeg)

+   让权重在第一次迭代开始时初始化为零。当网络通过从点 A 到 B 增加权重时，误差率开始减少。

+   一旦权重达到 B 点，误差率就变得最小。网络不断跟踪误差率。

+   进一步增加从点 B 到点 C 的权重后，网络意识到错误率再次开始增加。因此，网络停止更新其权重，并恢复到点 B 的权重，因为它们是最佳的。

+   在下一个场景中，考虑一种情况，即权重被随机初始化为某个值（比如说，点 C），如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00123.jpeg)

+   进一步增加这些随机权重后，错误也增加了（从点 C 开始并远离点 B，图中的小箭头表示）。

+   网络意识到错误增加，并开始从点 C 减小权重，以使错误减少（在图中从点 C 向点 B 移动的长箭头表示）。这种权重减少会一直持续，直到错误达到最小值（图中的点 B）。

+   网络继续在达到点 B 后进一步更新其权重（在图中从点 B 远离并向点 A 移动的箭头表示）。然后它意识到错误再次增加。因此，它停止权重更新，并恢复到给出最小错误值的权重（即点 B 处的权重）。

+   这是神经网络在反向传播后执行权重更新的方式。这种权重更新是基于动量的。它依赖于在每次迭代期间网络中每个神经元计算的梯度，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00124.jpeg)

基本上，每次输入流入神经元时，都会针对输出计算每个输入的梯度。链式法则用于在反向传播的后向传递期间计算梯度。

# 另请参阅

可以在以下链接找到反向传播背后的数学详细解释：

+   [`mattmazur.com/2015/03/17/a-step-by-step-backpropagation-example/`](https://mattmazur.com/2015/03/17/a-step-by-step-backpropagation-example/)

+   [`becominghuman.ai/back-propagation-is-very-simple-who-made-it-complicated-97b794c97e5`](https://becominghuman.ai/back-propagation-is-very-simple-who-made-it-complicated-97b794c97e5c)

Andrej Karpathy 的博客中有大量关于递归神经网络的有用信息。以下是一个解释它们不合理有效性的链接：

+   [`karpathy.github.io/2015/05/21/rnn-effectiveness/`](http://karpathy.github.io/2015/05/21/rnn-effectiveness/)

# 痛点＃1 - 梯度消失问题

递归神经网络非常适用于涉及序列数据的任务。然而，它们也有缺点。本节将重点讨论其中一个缺点，即**梯度消失问题**。

# 准备工作

梯度消失问题的名称源于在反向传播步骤中，一些梯度消失或变为零。从技术上讲，这意味着在网络的反向传播过程中没有错误项被向后传播。当网络变得更深更复杂时，这就成为了一个问题。

# 如何做...

本节将描述递归神经网络中梯度消失问题的发生方式：

+   在使用反向传播时，网络首先计算错误，这只是模型输出减去实际输出的平方（如平方误差）。

+   使用这个错误，模型然后计算错误相对于权重变化的变化（de/dw）。

+   计算得到的导数乘以学习率 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00125.jpeg) 得到 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00126.jpeg)w，这就是权重的变化。术语 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00127.jpeg)w 被添加到原始权重上，以将它们更新为新的权重。

+   假设 de/dw（错误相对于权重的梯度或变化率）的值远小于 1，那么该术语乘以学习率 ![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00128.jpeg) （始终远小于 1）得到一个非常小的可忽略的数字。

+   这是因为在反向传播过程中，权重更新仅对最近的时间步准确，而在通过以前的时间步进行反向传播时，准确性会降低，并且当权重更新通过许多时间步回溯时，这种准确性几乎变得微不足道。

+   在某些情况下，句子可能非常长，神经网络试图预测句子中的下一个单词。它基于句子的上下文进行预测，因此需要来自许多先前时间步的信息（这些被称为长期依赖）。网络需要通过的先前时间步数随着句子长度的增加而增加。在这种情况下，循环网络无法记住过去许多时间步的信息，因此无法进行准确的预测。

+   当出现这种情况时，网络需要进行更多复杂的计算，因此迭代次数大大增加，同时误差项的变化减少（随着时间的推移）并且权重的变化变得微不足道。因此，新的或更新的权重几乎等于先前的权重。

+   由于没有发生权重更新，网络停止学习或无法更新其权重，这是一个问题，因为这将导致模型过度拟合数据。

+   整个过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00130.jpeg)

# 它是如何工作的...

本节将描述梯度消失问题的一些后果：

1.  当我们使用一些基于梯度的优化技术训练神经网络模型时，就会出现这个问题。

1.  通常，增加更多的隐藏层倾向于使网络能够学习更复杂的任意函数，从而在预测未来结果方面做得更好。深度学习由于具有大量的隐藏层（从 10 到 200 个），因此产生了很大的影响。现在可以理解复杂的序列数据，并执行诸如语音识别、图像分类、图像字幕等任务。

1.  由前述步骤引起的问题是，在某些情况下，梯度变得非常小，几乎消失，这反过来阻止权重在未来时间步骤中更新其值。

1.  在最坏的情况下，这可能导致网络的训练过程停止，这意味着网络停止通过训练步骤学习不同的特征。

1.  反向传播的主要思想是，它允许我们作为研究人员监视和理解机器学习算法如何处理和学习各种特征。当梯度消失时，就不可能解释网络中发生了什么，因此识别和调试错误变得更加具有挑战性。

# 还有更多...

以下是解决梯度消失问题的一些方法：

+   一种方法在一定程度上克服这个问题是使用 ReLU 激活函数。它计算函数*f(x)=max(0,x)（即，激活函数简单地将输出的较低级别阈值设为零），并防止网络产生负梯度。

+   另一种克服这个问题的方法是对每个层进行无监督训练，然后通过反向传播对整个网络进行微调，就像 Jürgen Schmidhuber 在他对神经网络中多层次层次结构的研究中所做的那样。该论文的链接在下一节中提供。

+   解决这个问题的第三种方法是使用 LSTM（长短期记忆）单元或 GRUs（门控循环单元），这些是特殊类型的 RNN。

# 另请参阅

以下链接提供了对梯度消失问题的更深入描述，以及一些解决该问题的方法：

+   [`ayearofai.com/rohan-4-the-vanishing-gradient-problem-ec68f76ffb9b`](https://ayearofai.com/rohan-4-the-vanishing-gradient-problem-ec68f76ffb9b)

+   [`www.cs.toronto.edu/~rgrosse/courses/csc321_2017/readings/L15%20Exploding%20and%20Vanishing%20Gradients.pdf`](http://www.cs.toronto.edu/~rgrosse/courses/csc321_2017/readings/L15%20Exploding%20and%20Vanishing%20Gradients.pdf)

+   [`people.idsia.ch/~juergen/cvpr2012.pdf`](http://people.idsia.ch/~juergen/cvpr2012.pdf)

# 痛点＃2 - 爆炸梯度问题

递归神经网络的另一个缺点是爆炸梯度问题。这与梯度消失问题类似，但完全相反。有时在反向传播过程中，梯度会爆炸成异常大的值。与梯度消失问题一样，爆炸梯度问题发生在网络架构变得更深时。

# 准备工作

爆炸梯度问题的名称源于反向传播步骤中一些梯度消失或变为零的事实。从技术上讲，这意味着在网络的反向传播过程中没有误差项向后传播。当网络变得更深更复杂时，这就成为了一个问题。

# 如何做...

本节将描述递归神经网络中的爆炸梯度问题：

+   爆炸梯度问题与梯度消失问题非常相似，但完全相反。

+   当递归神经网络中出现长期依赖时，误差项向后传播时有时会爆炸或变得非常大。

+   这个误差项乘以学习率的结果是一个极端大的![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00131.jpeg)w。这导致产生的新权重看起来与以前的权重非常不同。这被称为爆炸梯度问题，因为梯度的值变得太大。

+   爆炸梯度问题以算法方式在以下图表中进行了说明：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00132.jpeg)

# 工作原理...

由于神经网络使用基于梯度的优化技术来学习数据中存在的特征，因此必须保留这些梯度，以便网络根据梯度的变化计算误差。本节将描述爆炸梯度问题在递归神经网络中是如何发生的：

+   在使用反向传播时，网络首先计算误差，这只是模型输出减去实际输出的平方（如平方误差）。

+   使用这个误差，模型然后计算了相对于权重变化的误差变化（de/dw）。

+   计算得到的导数乘以学习率![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00133.jpeg)得到![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00134.jpeg)w，这只是权重的变化。项![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00135.jpeg)w 被添加到原始权重上，以将它们更新为新的权重。

+   假设 de/dw（误差相对于权重的梯度或变化率）的值大于 1，那么该项乘以学习率![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00136.jpeg)将得到一个非常非常大的数字，对于网络在进一步优化权重时是毫无用处的，因为权重已不再处于相同的范围内。

+   这是因为在反向传播过程中，权重更新仅对最近的时间步准确，而在通过以前的时间步进行反向传播时，这种准确性会降低，并且当权重更新通过许多时间步回溯时几乎变得无关紧要。

+   网络需要通过的以前时间步数随着输入数据中序列数量的增加而增加。在这种情况下，递归网络无法记住过去许多时间步的信息，因此无法准确预测未来时间步。

+   当出现这种情况时，网络需要进行更多复杂的计算，因此迭代次数大大增加，错误项的变化超过 1，权重（w）的变化激增。结果，与先前的权重相比，新的或更新的权重完全超出范围。

+   由于没有发生权重更新，网络停止学习或无法在指定范围内更新其权重，这是一个问题，因为这将导致模型过度拟合数据。

# 还有更多...

以下是解决梯度爆炸问题的一些方法：

+   可以应用某些梯度裁剪技术来解决梯度爆炸的问题。

+   另一种预防方法是使用截断的时间反向传播，而不是从最后一个时间步（或输出层）开始反向传播，我们可以选择一个较小的时间步（比如 15）开始反向传播。这意味着网络将一次只反向传播最后的 15 个时间步，并且只学习与这 15 个时间步相关的信息。这类似于将小批量数据馈送到网络中，因为在大型数据集的情况下，计算每个数据集元素的梯度将变得过于昂贵。

+   防止梯度爆炸的最后一种选择是监控它们并相应地调整学习率。

# 另请参阅

可以在以下链接找到有关消失和爆炸梯度问题的更详细解释：

+   [`neuralnetworksanddeeplearning.com/chap5.html`](http://neuralnetworksanddeeplearning.com/chap5.html)

+   [`www.dlology.com/blog/how-to-deal-with-vanishingexploding-gradients-in-keras/`](https://www.dlology.com/blog/how-to-deal-with-vanishingexploding-gradients-in-keras/)

+   [`machinelearningmastery.com/exploding-gradients-in-neural-networks/`](https://machinelearningmastery.com/exploding-gradients-in-neural-networks/)

# LSTMs 的顺序工作

**长短期记忆单元**（**LSTM**）单元只是相对于循环网络而言稍微更先进的架构。LSTMs 可以被认为是一种具有学习顺序数据中存在的长期依赖关系能力的特殊类型的循环神经网络。其主要原因是 LSTMs 包含内存，并且能够存储和更新其单元内的信息，而不像循环神经网络那样。

# 准备好了

长短期记忆单元的主要组成部分如下：

+   输入门

+   遗忘门

+   更新门

这些门中的每一个都由一个 S 形层和一个逐点乘法操作组成。S 形层输出介于零和一之间的数字。这些值描述了每个组件的信息有多少被允许通过相应的门。值为零意味着门不允许任何信息通过，而值为一意味着门允许所有信息通过。

了解 LSTM 单元的最佳方法是通过计算图，就像循环神经网络的情况一样。

LSTMs 最初是由 Sepp Hochreiter 和 Jurgen Schmidhuber 于 1997 年开发的。以下是他们发表的论文链接：

+   [`www.bioinf.jku.at/publications/older/2604.pdf`](http://www.bioinf.jku.at/publications/older/2604.pdf)

# 如何做...

本节将描述单个 LSTM 单元的内部组件，主要是单元内部存在的三个不同门。一系列这样的单元堆叠在一起形成一个 LSTM 网络：

1.  LSTMs 也像 RNNs 一样具有链式结构。标准 RNN 基本上是重复单元的模块，如简单函数（例如 tanh）。

1.  与 RNN 相比，由于每个单元中存在内存，LSTM 具有比 RNN 更长时间地保留信息的能力。这使它们能够在输入序列的早期阶段学习重要信息，并且还赋予了它们在每个时间步的决策中产生重要影响的能力。

1.  通过能够从输入序列的早期阶段存储信息，LSTM 能够积极地保留可以通过时间和层进行反向传播的错误，而不是让该错误消失或爆炸。

1.  LSTM 能够在许多时间步长上学习信息，因此通过保留通过这些层进行反向传播的错误，具有更密集的层架构。

1.  细胞结构称为**“门”**赋予了 LSTM 保留信息、添加信息或从**细胞状态**中删除信息的能力。

1.  以下图示了 LSTM 的结构。在尝试理解 LSTM 时的关键特征在于理解 LSTM 网络架构和细胞状态，可以在这里进行可视化：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00138.gif)

1.  在前面的图中，*x[t]*和*h[t-1]*是细胞的两个输入。*x*[*t*]是当前时间步的输入，而*h[t-1]*是上一个时间步的输入（即上一个时间步的细胞的输出）。除了这两个输入，我们还有*h*[, ]，它是经过门控循环单元（LSTM）细胞对这两个输入进行操作后的当前输出（即时间步 t）。

1.  在前面的图中，r[t]表示从输入门中出现的输出，它接受*h*[*t-1*]和*x[t]*的输入，将这些输入与其权重矩阵*W[z]*相乘，并通过 S 形激活函数传递。

1.  类似地，术语*z[t]*表示从遗忘门中出现的输出。这个门有一组权重矩阵（由*W[r]*表示），这些权重矩阵特定于这个特定的门，并控制门的功能。

1.  最后，还有![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00139.jpeg)[t]，它是从更新门中出现的输出。在这种情况下，有两个部分。第一部分是一个称为**输入门层**的 S 形层，其主要功能是决定要更新哪些值。下一层是一个 tanh 层。这一层的主要功能是创建一个包含可以添加到细胞状态中的新值的向量或数组。

# 它是如何工作的...

一系列 LSTM 细胞/单元的组合形成了 LSTM 网络。这种网络的架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00140.jpeg)

1.  在前面的图中，完整的 LSTM 细胞由***“A”***表示。细胞接受输入序列的当前输入（*x**[i]*），并产生（*h**[i]*），这实际上就是当前隐藏状态的输出。然后将此输出作为下一个 LSTM 细胞的输入。

1.  LSTM 细胞比 RNN 细胞稍微复杂一些。RNN 细胞只有一个作用于当前输入的功能/层，而 LSTM 细胞有三个层，即控制细胞在任何给定时间点流动的三个门。

1.  细胞的行为很像计算机中的硬盘内存。因此，细胞具有允许在其细胞状态内写入、读取和存储信息的能力。细胞还会决定存储哪些信息，以及何时允许读取、写入和擦除信息。这是通过相应地打开或关闭门来实现的。

1.  LSTM 细胞中的门是模拟的，与当今计算机中的数字存储系统形成对比。这意味着门只能通过 S 形函数的逐元素乘法来控制，产生介于 0 和 1 之间的概率值。高值将导致门保持打开，而低值将导致门保持关闭。

1.  模拟系统在神经网络操作方面比数字系统更具优势，因为它们是可微分的。这使得模拟系统更适合像反向传播这样主要依赖于梯度的任务。

1.  门传递信息或阻止信息，或者只让部分信息根据其强度和重要性流过它们。每一次时间步骤，信息都会通过特定于每个门的权重矩阵集合进行过滤。因此，每个门都完全控制如何对接收到的信息进行操作。

1.  与每个门相关的权重矩阵，如调制输入和隐藏状态的权重，都是根据递归网络的学习过程和梯度下降进行调整的。

1.  第一个门被称为“遗忘门”，它控制从上一个状态中保留哪些信息。该门将上一个细胞的输出（*h**[t]** - 1*）作为其输入，以及当前输入（*x**[t]*），并应用 sigmoid 激活（![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00141.jpeg)）以产生每个隐藏单元的 0 到 1 之间的输出值。然后进行与当前状态的逐元素乘法（在前面图表中的第一个操作中说明）。

1.  第二个门被称为“更新门”，其主要功能是根据当前输入更新细胞状态。该门将与遗忘门的输入相同的输入（*h**[t-1]*和*x**[t]*）传递到一个 sigmoid 激活层（![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00141.jpeg)），然后经过 tanh 激活层，并对这两个结果进行逐元素乘法。接下来，将结果与当前状态进行逐元素加法（在前面图表中的第二个操作中说明）。

1.  最后，有一个输出门，它控制传递到相邻细胞的信息和信息量，以作为下一个时间步骤的输入。当前细胞状态通过 tanh 激活层传递，并在通过 sigmoid 层（![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00141.jpeg)）进行此操作后，与细胞输入（*h**[t-1]*和*x**[t]*）进行逐元素乘法。

1.  更新门的行为就像细胞决定输出到下一个细胞的过滤器。这个输出 h[t]然后传递给下一个 LSTM 细胞作为它的输入，并且如果许多 LSTM 细胞堆叠在一起，也传递给上面的层。

# 还有更多...

与前馈网络和循环神经网络相比，LSTM 是一个重大的飞跃。人们可能会想知道未来的下一个重大进步是什么，甚至可能是什么。许多研究人员认为，“注意力”是人工智能领域的下一个重大进步。随着每天数据量的急剧增长，处理每一位数据变得不可能。这就是注意力可能成为潜在的游戏改变者的地方，使网络只关注高优先级或感兴趣的数据或区域，并忽略无用的信息。例如，如果一个 RNN 被用来创建图像字幕引擎，它将只选择图像的一部分来关注，以便输出每个单词。

徐等人在 2015 年的最新论文正是这样做的。他们探索了在 LSTM 细胞中添加注意力。阅读这篇论文可以是学习神经网络中使用注意力的好起点。在各种任务中使用注意力已经取得了一些良好的结果，目前正在对该主题进行更多的研究。徐等人的论文可以通过以下链接找到：

[`arxiv.org/pdf/1502.03044v2.pdf`](https://arxiv.org/pdf/1502.03044v2.pdf)

注意力并不是 LSTM 的唯一变体。一些其他活跃的研究是基于格子 LSTM 的利用，正如 Kalchbrenner 等人在其论文中使用的那样，链接在：[`arxiv.org/pdf/1507.01526v1.pdf`](https://arxiv.org/pdf/1507.01526v1.pdf)。

# 另请参阅

关于生成网络中的 RNN 和 LSTM 的其他有用信息和论文可以通过访问以下链接找到：

+   [`www.deeplearningbook.org/contents/rnn.html`](http://www.deeplearningbook.org/contents/rnn.html)

+   [`arxiv.org/pdf/1502.04623.pdf`](https://arxiv.org/pdf/1502.04623.pdf)

+   [`arxiv.org/pdf/1411.7610v3.pdf`](https://arxiv.org/pdf/1411.7610v3.pdf)

+   [`arxiv.org/pdf/1506.02216v3.pdf`](https://arxiv.org/pdf/1506.02216v3.pdf)


# 第五章：使用 Spark ML 预测消防部门呼叫

在本章中，将涵盖以下内容：

+   下载旧金山消防部门呼叫数据集

+   识别逻辑回归模型的目标变量

+   为逻辑回归模型准备特征变量

+   应用逻辑回归模型

+   评估逻辑回归模型的准确性

# 介绍

分类模型是预测定义的分类结果的一种流行方式。我们经常使用分类模型的输出。每当我们去电影院看电影时，我们都想知道这部电影是否被认为是正确的？数据科学社区中最流行的分类模型之一是逻辑回归。逻辑回归模型产生的响应由 S 形函数激活。S 形函数使用模型的输入并产生一个在 0 和 1 之间的输出。该输出通常以概率分数的形式呈现。许多深度学习模型也用于分类目的。通常会发现逻辑回归模型与深度学习模型一起执行，以帮助建立深度学习模型的基线。S 形激活函数是深度学习中使用的许多激活函数之一，用于产生概率输出。我们将利用 Spark 内置的机器学习库构建一个逻辑回归模型，该模型将预测旧金山消防部门的呼叫是否实际与火灾有关，而不是其他事件。

# 下载旧金山消防部门呼叫数据集

旧金山市在整个地区收集消防部门的服务呼叫记录做得非常好。正如他们的网站上所述，每条记录包括呼叫编号、事件编号、地址、单位标识符、呼叫类型和处理结果。包含旧金山消防部门呼叫数据的官方网站可以在以下链接找到：

[`data.sfgov.org/Public-Safety/Fire-Department-Calls-for-Service/nuek-vuh3`](https://data.sfgov.org/Public-Safety/Fire-Department-Calls-for-Service/nuek-vuh3)

有关数据集的一些一般信息，包括列数和行数，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00142.jpeg)

这个当前数据集，更新于 2018 年 3 月 26 日，大约有 461 万行和 34 列。

# 准备工作

数据集以`.csv`文件的形式可供下载，并可在本地机器上下载，然后导入 Spark。

# 操作步骤如下：

本节将介绍下载和导入`.csv`文件到我们的 Jupyter 笔记本的步骤。

1.  通过选择导出然后 CSV 从网站下载数据集，如下截图所示： 

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00143.jpeg)

1.  如果还没有这样做，请将下载的数据集命名为`Fire_Department_Calls_for_Service.csv`

1.  将数据集保存到任何本地目录，尽管理想情况下应该保存到包含本章中将使用的 Spark 笔记本的相同文件夹中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00144.jpeg)

1.  一旦数据集已保存到与笔记本相同的目录中，执行以下`pyspark`脚本将数据集导入 Spark 并创建一个名为`df`的数据框：

```scala
from pyspark.sql import SparkSession
spark = SparkSession.builder \
                    .master("local") \
                    .appName("Predicting Fire Dept Calls") \
                    .config("spark.executor.memory", "6gb") \
                    .getOrCreate()

df = spark.read.format('com.databricks.spark.csv')\
                    .options(header='true', inferschema='true')\
                    .load('Fire_Department_Calls_for_Service.csv')
df.show(2)
```

# 工作原理如下：

数据集保存在与 Jupyter 笔记本相同的目录中，以便轻松导入到 Spark 会话中。

1.  通过从`pyspark.sql`导入`SparkSession`来初始化本地`pyspark`会话。

1.  通过使用选项`header='true'`和`inferschema='true'`读取 CSV 文件创建一个名为`df`的数据框。

1.  最后，始终最好运行一个脚本来显示已通过数据框导入 Spark 的数据，以确认数据已传输。可以在以下截图中看到该脚本的结果，显示了来自旧金山消防局呼叫的数据集的前两行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00145.jpeg)

请注意，当我们将文件读入 spark 时，我们使用`.load()`将`.csv`文件拉入 Jupyter 笔记本。对于我们的目的来说，这是可以的，因为我们使用的是本地集群，但如果我们要利用 Hadoop 中的集群，这种方法就行不通了。

# 还有更多...

数据集附带有数据字典，定义了 34 列的标题。可以通过以下链接从同一网站访问此数据字典：

[`data.sfgov.org/api/views/nuek-vuh3/files/ddb7f3a9-0160-4f07-bb1e-2af744909294?download=true&filename=FIR-0002_DataDictionary_fire-calls-for-service.xlsx`](https://data.sfgov.org/api/views/nuek-vuh3/files/ddb7f3a9-0160-4f07-bb1e-2af744909294?download=true&filename=FIR-0002_DataDictionary_fire-calls-for-service.xlsx)

# 另请参阅

旧金山政府网站允许在线可视化数据，可用于进行一些快速数据概要分析。可以通过选择可视化下拉菜单在网站上访问可视化应用程序，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00146.jpeg)

# 识别逻辑回归模型的目标变量

逻辑回归模型作为分类算法运行，旨在预测二进制结果。在本节中，我们将指定数据集中用于预测运营商呼入电话是否与火灾或非火灾事件相关的最佳列。

# 准备就绪

在本节中，我们将可视化许多数据点，这将需要以下操作：

1.  通过在命令行中执行`pip install matplotlib`来确保安装了`matplotlib`。

1.  运行`import matplotlib.pyplot as plt`，并确保通过运行`%matplotlib inline`在单元格中查看图形。

此外，将对`pyspark.sql`中的函数进行一些操作，需要`importing functions as F`。

# 如何做...

本节将介绍如何可视化来自旧金山消防局的数据。

1.  执行以下脚本以对`Call Type Group`列中唯一值进行快速识别：

```scala
df.select('Call Type Group').distinct().show()
```

1.  有五个主要类别：

1.  `警报`。

1.  `潜在危及生命`。

1.  `非危及生命`。

1.  `火`。

1.  `null`。

1.  不幸的是，其中一个类别是`null`值。有必要获取每个唯一值的行计数，以确定数据集中有多少`null`值。执行以下脚本以生成`Call Type Group`列的每个唯一值的行计数：

```scala
df.groupBy('Call Type Group').count().show()
```

1.  不幸的是，有超过 280 万行数据没有与之关联的`呼叫类型组`。这超过了 460 万可用行的 60％。执行以下脚本以查看条形图中空值的不平衡情况：

```scala
df2 = df.groupBy('Call Type Group').count()
graphDF = df2.toPandas()
graphDF = graphDF.sort_values('count', ascending=False)

import matplotlib.pyplot as plt
%matplotlib inline

graphDF.plot(x='Call Type Group', y = 'count', kind='bar')
plt.title('Call Type Group by Count')
plt.show()
```

1.  可能需要选择另一个指标来确定目标变量。相反，我们可以对`Call Type`进行概要分析，以识别与火灾相关的呼叫与所有其他呼叫。执行以下脚本以对`Call Type`进行概要分析：

```scala
df.groupBy('Call Type').count().orderBy('count', ascending=False).show(100)
```

1.  与`Call Type Group`一样，似乎没有任何`null`值。`Call Type`有 32 个唯一类别；因此，它将被用作火灾事件的目标变量。执行以下脚本以标记包含`Fire`的`Call Type`列：

```scala
from pyspark.sql import functions as F
fireIndicator = df.select(df["Call Type"],F.when(df["Call Type"].like("%Fire%"),1)\
                          .otherwise(0).alias('Fire Indicator'))
fireIndicator.show()
```

1.  执行以下脚本以检索`Fire Indicator`的不同计数：

```scala
fireIndicator.groupBy('Fire Indicator').count().show()
```

1.  执行以下脚本以将`Fire Indicator`列添加到原始数据框`df`中：

```scala
df = df.withColumn("fireIndicator",\ 
F.when(df["Call Type"].like("%Fire%"),1).otherwise(0))
```

1.  最后，将`fireIndicator`列添加到数据框`df`中，并通过执行以下脚本进行确认：

```scala
df.printSchema()
```

# 它是如何工作的...

建立成功的逻辑回归模型的关键步骤之一是建立一个二元目标变量，该变量将用作预测结果。本节将介绍选择目标变量背后的逻辑：

1.  通过识别`Call Type Group`的唯一列值来执行潜在目标列的数据概要分析。我们可以查看`Call Type Group`列的唯一值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00147.jpeg)

1.  目标是确定`Call Type Group`列中是否存在缺失值，以及如何处理这些缺失值。有时，可以直接删除列中的缺失值，而其他时候可以对其进行处理以填充值。

1.  以下截图显示了存在多少空值：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00148.jpeg)

1.  此外，我们还可以绘制存在多少`null`值，以更好地直观感受值的丰富程度，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00149.jpeg)

1.  由于`Call Type Group`中有超过 280 万行缺失，如`df.groupBy`脚本和条形图所示，删除所有这些值是没有意义的，因为这超过了数据集的总行数的 60%。因此，需要选择另一列作为目标指示器。

1.  在对`Call Type`列进行数据概要分析时，我们发现 32 个可能值中没有空行。这使得`Call Type`成为逻辑回归模型的更好目标变量候选项。以下是`Call Type`列的数据概要分析截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00150.jpeg)

1.  由于逻辑回归在有二元结果时效果最佳，因此使用`withColumn()`操作符在`df`数据框中创建了一个新列，以捕获与火灾相关事件或非火灾相关事件相关的指示器（0 或 1）。新列名为`fireIndicator`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00151.jpeg)

1.  我们可以通过执行`groupBy().count()`来确定火警呼叫与其他呼叫的普遍程度，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00152.jpeg)

1.  最佳实践是通过执行新修改的数据框的`printSchema()`脚本来确认新列是否已附加到现有数据框。新模式的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00153.jpeg)

# 还有更多...

在本节中，使用`pyspark.sql`模块进行了一些列操作。`withColumn()`操作符通过添加新列或修改同名现有列来返回新的数据框，或修改现有数据框。这与`withColumnRenamed()`操作符不同，后者也返回新的数据框，但是通过修改现有列的名称为新列。最后，我们需要执行一些逻辑操作，将与`Fire`相关的值转换为 0，没有`Fire`的值转换为 1。这需要使用`pyspark.sql.functions`模块，并将`where`函数作为 SQL 中 case 语句的等价物。该函数使用以下语法创建了一个 case 语句方程：

```scala
CASE WHEN Call Type LIKE %Fire% THEN 1 ELSE 0 END
```

新数据集的结果，`Call Type`和`fireIndicator`两列如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00154.jpeg)

# 另请参阅

要了解更多关于 Spark 中可用的`pyspark.sql`模块的信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/api/python/pyspark.sql.html`](http://spark.apache.org/docs/2.2.0/api/python/pyspark.sql.html)

# 为逻辑回归模型准备特征变量

在上一节中，我们确定了将用作逻辑回归模型预测结果的目标变量。本节将重点关注确定所有最有助于模型确定目标的特征。这被称为**特征选择**。

# 准备工作

本节将需要从`pyspark.ml.feature`中导入`StringIndexer`。为了确保正确的特征选择，我们需要将字符串列映射到索引列。这将有助于为分类变量生成不同的数值，从而为机器学习模型提供独立变量的计算便利，用于预测目标结果。

# 如何操作...

本节将逐步介绍为我们的模型准备特征变量的步骤。

1.  执行以下脚本来更新数据框`df`，只选择与任何火灾指示无关的字段：

```scala
df = df.select('fireIndicator', 
    'Zipcode of Incident',
    'Battalion',
    'Station Area',
    'Box', 
    'Number of Alarms',
    'Unit sequence in call dispatch',
    'Neighborhooods - Analysis Boundaries',
    'Fire Prevention District',
    'Supervisor District')
df.show(5)
```

1.  下一步是识别数据框中的任何空值并在存在时删除它们。执行以下脚本来识别具有任何空值的行数：

```scala
print('Total Rows')
df.count()
print('Rows without Null values')
df.dropna().count()
print('Row with Null Values')
df.count()-df.dropna().count()
```

1.  有 16,551 行具有缺失值。执行以下脚本来更新数据框以删除所有具有空值的行：

```scala
df = df.dropna()
```

1.  执行以下脚本来检索`fireIndicator`的更新目标计数：

```scala
df.groupBy('fireIndicator').count().orderBy('count', ascending = False).show()
```

1.  从`pyspark.ml.feature`中导入`StringIndexer`类，为特征分配数值，如下脚本所示：

```scala
from pyspark.ml.feature import StringIndexer
```

1.  使用以下脚本为模型创建所有特征变量的 Python 列表：

```scala
column_names = df.columns[1:]
```

1.  执行以下脚本来指定输出列格式`outputcol`，它将从输入列`inputcol`的特征列表中进行`stringIndexed`：

```scala
categoricalColumns = column_names
indexers = []
for categoricalCol in categoricalColumns:
    stringIndexer = StringIndexer(inputCol=categoricalCol, outputCol=categoricalCol+"_Index")
    indexers += [stringIndexer]
```

1.  执行以下脚本创建一个`model`，用于`fit`输入列并为现有数据框`df`生成新定义的输出列：

```scala
models = []
for model in indexers:
    indexer_model = model.fit(df)
    models+=[indexer_model]

for i in models:
    df = i.transform(df)
```

1.  执行以下脚本来定义数据框`df`中将用于模型的特征的最终选择：

```scala
df = df.select(
          'fireIndicator',
          'Zipcode of Incident_Index',
          'Battalion_Index',
          'Station Area_Index',
          'Box_Index',
          'Number of Alarms_Index',
          'Unit sequence in call dispatch_Index',
          'Neighborhooods - Analysis Boundaries_Index',
          'Fire Prevention District_Index',
          'Supervisor District_Index')
```

# 工作原理...

本节将解释为我们的模型准备特征变量的步骤背后的逻辑。

1.  只选择数据框中真正与火灾指示无关的指标，以贡献于预测结果的逻辑回归模型。执行此操作的原因是为了消除数据集中可能已经显示预测结果的任何潜在偏见。这最小化了人为干预最终结果。更新后的数据框的输出可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00155.jpeg)

请注意，列`邻里-分析边界`在我们提取的数据中原本拼写错误。出于连续性目的，我们将继续使用拼写错误。但是，可以使用 Spark 中的`withColumnRenamed()`函数来重命名列名。

1.  最终选择的列如下所示：

+   `火灾指示`

+   `事故邮政编码`

+   `大队`

+   `站点区域`

+   `箱`

+   `警报数量`

+   `呼叫调度中的单位序列`

+   `邻里-分析边界`

+   `消防预防区`

+   `监管区`

1.  选择这些列是为了避免我们建模中的数据泄漏。数据泄漏在建模中很常见，可能导致无效的预测模型，因为它可能包含直接由我们试图预测的结果产生的特征。理想情况下，我们希望包含真正与结果无关的特征。有几列似乎是有泄漏的，因此从我们的数据框和模型中删除了这些列。

1.  识别并删除所有具有缺失或空值的行，以便在不夸大或低估关键特征的情况下获得模型的最佳性能。可以计算并显示具有缺失值的行的清单，如下脚本所示，数量为 16,551：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00156.jpeg)

1.  我们可以看一下与火灾相关的呼叫频率与非火灾相关的呼叫频率，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00157.jpeg)

1.  导入`StringIndexer`以帮助将几个分类或字符串特征转换为数字值，以便在逻辑回归模型中进行计算。特征的输入需要以向量或数组格式，这对于数字值是理想的。可以在以下屏幕截图中看到将在模型中使用的所有特征的列表：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00158.jpeg)

1.  为每个分类变量构建了一个索引器，指定了模型中将使用的输入（`inputCol`）和输出（`outputCol`）列。数据框中的每一列都会被调整或转换，以重新构建一个具有更新索引的新输出，范围从 0 到该特定列的唯一计数的最大值。新列在末尾附加了`_Index`。在创建更新的列的同时，原始列仍然可在数据框中使用，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00159.jpeg)

1.  我们可以查看其中一个新创建的列，并将其与原始列进行比较，以查看字符串是如何转换为数字类别的。以下屏幕截图显示了`Neighborhooods - Analysis Boundaries`与`Neighborhooods - Analysis Boundaries_Index`的比较：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00160.jpeg)

1.  然后，数据框被修剪以仅包含数字值，并删除了转换的原始分类变量。非数字值从建模的角度来看不再有意义，并且从数据框中删除。

1.  打印出新列以确认数据框的每个值类型都是双精度或整数，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00161.jpeg)

# 还有更多...

最终查看新修改的数据框将只显示数字值，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00162.jpeg)

# 另请参阅

要了解更多关于`StringIndexer`的信息，请访问以下网站：[`spark.apache.org/docs/2.2.0/ml-features.html#stringindexer`](https://spark.apache.org/docs/2.2.0/ml-features.html#stringindexer)。

# 应用逻辑回归模型

现在已经准备好将模型应用于数据框。

# 准备工作

本节将重点介绍一种非常常见的分类模型，称为**逻辑回归**，这将涉及从 Spark 中导入以下内容：

```scala
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.classification import LogisticRegression
```

# 如何做...

本节将介绍应用我们的模型和评估结果步骤。

1.  执行以下脚本，将数据框中的所有特征变量汇总到名为`features`的列表中：

```scala
features = df.columns[1:]
```

1.  执行以下操作以导入`VectorAssembler`并配置将被分配给特征向量的字段，通过分配`inputCols`和`outputCol`：

```scala
from pyspark.ml.feature import VectorAssembler
feature_vectors = VectorAssembler(
    inputCols = features,
    outputCol = "features")
```

1.  执行以下脚本，将`VectorAssembler`应用于数据框，并使用`transform`函数：

```scala
df = feature_vectors.transform(df)
```

1.  修改数据框，删除除`fireIndicator`和`features`之外的所有列，如下脚本所示：

```scala
df = df.drop( 'Zipcode of Incident_Index',
              'Battalion_Index',
              'Station Area_Index',
              'Box_Index',
              'Number of Alarms_Index',
              'Unit sequence in call dispatch_Index',
              'Neighborhooods - Analysis Boundaries_Index',
              'Fire Prevention District_Index',
              'Supervisor District_Index')
```

1.  修改数据框，将`fireIndicator`重命名为`label`，如下脚本所示：

```scala
df = df.withColumnRenamed('fireIndicator', 'label')
```

1.  将整个数据框`df`分割为 75:25 的训练和测试集，随机种子设置为`12345`，如下脚本所示：

```scala
(trainDF, testDF) = df.randomSplit([0.75, 0.25], seed = 12345)
```

1.  从`pyspark.ml.classification`中导入`LogisticRegression`库，并配置以将数据框中的`label`和`features`合并，然后在训练数据集`trainDF`上拟合，如下脚本所示：

```scala
from pyspark.ml.classification import LogisticRegression
logreg = LogisticRegression(labelCol="label", featuresCol="features", maxIter=10)
LogisticRegressionModel = logreg.fit(trainDF)
```

1.  转换测试数据框`testDF`以应用逻辑回归模型。具有预测得分的新数据框称为`df_predicted`，如下脚本所示：

```scala
df_predicted = LogisticRegressionModel.transform(testDF)
```

# 它是如何工作的...

本节将解释应用我们的模型和评估结果步骤背后的逻辑。

1.  当所有特征被合并为单个向量进行训练时，分类模型的效果最佳。因此，我们通过将所有特征收集到一个名为`features`的列表中开始向量化过程。由于我们的标签是数据框的第一列，我们将其排除，并将其后的每一列作为特征列或特征变量引入。

1.  向量化过程继续，将`features`列表中的所有变量转换为名为`features`的单个向量输出到列中。此过程需要从`pyspark.ml.feature`导入`VectorAssembler`。

1.  应用`VectorAssembler`转换数据框，创建一个名为`features`的新添加列，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00163.jpeg)

1.  在这一点上，我们在模型中需要使用的唯一列是标签列`fireIndicator`和`features`列。数据框中的所有其他列都可以删除，因为它们在建模过程中将不再需要。

1.  此外，为了帮助逻辑回归模型，我们将名为`fireIndicator`的列更改为`label`。可以在以下截图中看到`df.show()`脚本的输出，其中包含新命名的列：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00164.jpeg)

1.  为了最小化过拟合模型，数据框将被拆分为测试和训练数据集，以在训练数据集`trainDF`上拟合模型，并在测试数据集`testDF`上进行测试。设置随机种子为`12345`，以确保每次执行单元格时随机性保持一致。可以在以下截图中看到数据拆分的行数：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00165.jpeg)

1.  然后，从`pyspark.ml.classification`导入逻辑回归模型`LogisticRegression`，并配置以从与特征和标签相关的数据框中输入适当的列名。此外，逻辑回归模型分配给一个名为`logreg`的变量，然后拟合以训练我们的数据集`trainDF`。

1.  基于测试数据框`testDF`的转换，创建一个名为`predicted_df`的新数据框，一旦逻辑回归模型对其进行评分。该模型为`predicted_df`创建了三个额外的列，基于评分。这三个额外的列是`rawPrediction`、`probability`和`prediction`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00166.jpeg)

1.  最后，可以对`df_predicted`中的新列进行概要，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00167.jpeg)

# 还有更多...

需要牢记的一件重要事情是，因为它可能最初看起来有些违反直觉，我们的概率阈值在数据框中设置为 50%。任何概率为 0.500 及以上的呼叫都会被预测为 0.0，任何概率小于 0.500 的呼叫都会被预测为 1.0。这是在管道开发过程中设置的，只要我们知道阈值是多少以及如何分配预测，我们就没问题。

# 另请参阅

要了解有关`VectorAssembler`的更多信息，请访问以下网站：

[`spark.apache.org/docs/latest/ml-features.html#vectorassembler`](https://spark.apache.org/docs/latest/ml-features.html#vectorassembler)

# 评估逻辑回归模型的准确性

现在我们准备好评估预测呼叫是否被正确分类为火灾事件的性能。

# 准备工作

我们将执行模型分析，需要导入以下内容：

+   `from sklearn import metrics`

# 如何做...

本节将逐步介绍评估模型性能的步骤。

1.  使用`.crosstab()`函数创建混淆矩阵，如下脚本所示：

```scala
df_predicted.crosstab('label', 'prediction').show()
```

1.  从`sklearn`导入`metrics`以帮助使用以下脚本衡量准确性：

```scala
from sklearn import metrics
```

1.  为了衡量准确性，从数据框中创建`actual`和`predicted`列的两个变量，使用以下脚本：

```scala
actual = df_predicted.select('label').toPandas()
predicted = df_predicted.select('prediction').toPandas()
```

1.  使用以下脚本计算准确度预测分数：

```scala
metrics.accuracy_score(actual, predicted)
```

# 它是如何工作的...

本节解释了如何评估模型性能。

1.  为了计算我们模型的准确度，重要的是能够确定我们的预测有多准确。通常，最好使用混淆矩阵交叉表来可视化，显示正确和错误的预测分数。我们使用`df_predicted`数据框的`crosstab()`函数创建一个混淆矩阵，它显示我们对标签为 0 的有 964,980 个真负预测，对标签为 1 的有 48,034 个真正预测，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00168.jpeg)

1.  我们从本节前面知道`testDF`数据框中共有 1,145,589 行；因此，我们可以使用以下公式计算模型的准确度：*(TP + TN) / 总数*。准确度为 88.4%。

1.  需要注意的是，并非所有的假分数都是相等的。例如，将一个呼叫分类为与火灾无关，最终却与火灾有关，比相反的情况对火灾安全的影响更大。这被称为假阴性。有一个考虑**假阴性**（**FN**）的指标，称为**召回率**。

1.  虽然我们可以手动计算准确度，如最后一步所示，但最好是自动计算准确度。这可以通过导入`sklearn.metrics`来轻松实现，这是一个常用于评分和模型评估的模块。

1.  `sklearn.metrics`接受两个参数，我们拥有标签的实际结果和从逻辑回归模型中得出的预测值。因此，创建了两个变量`actual`和`predicted`，并使用`accuracy_score()`函数计算准确度分数，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00169.jpeg)

1.  准确度分数与我们手动计算的相同，为 88.4%。

# 还有更多...

现在我们知道我们的模型能够准确预测呼叫是否与火灾相关的比率为 88.4%。起初，这可能听起来是一个强有力的预测；然而，将其与一个基准分数进行比较总是很重要，其中每个呼叫都被预测为非火灾呼叫。预测的数据框`df_predicted`中标签`1`和`0`的分布如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00170.jpeg)

我们可以对同一数据框运行一些统计，使用`df_predicted.describe('label').show()`脚本得到值为`1`的标签出现的平均值。该脚本的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00171.jpeg)

基础模型的预测值为`1`的比率为 14.94%，换句话说，它对值为 0 的预测率为*100 - 14.94*%，即 85.06%。因此，由于 85.06%小于模型的预测率 88.4%，这个模型相比于盲目猜测呼叫是否与火灾相关提供了改进。

# 另请参阅

要了解更多关于准确度与精确度的信息，请访问以下网站：

[`www.mathsisfun.com/accuracy-precision.html`](https://www.mathsisfun.com/accuracy-precision.html)


# 第六章：在生成网络中使用 LSTMs

阅读完本章后，您将能够完成以下任务：

+   下载将用作输入文本的小说/书籍

+   准备和清理数据

+   对句子进行标记化

+   训练并保存 LSTM 模型

+   使用模型生成类似的文本

# 介绍

由于**循环神经网络**（**RNNs**）在反向传播时存在一些缺点，**长短期记忆单元**（**LSTMs**）和**门控循环单元**（**GRUs**）在学习顺序输入数据时近来变得越来越受欢迎，因为它们更适合解决梯度消失和梯度爆炸的问题。

# 下载将用作输入文本的小说/书籍

在本示例中，我们将介绍下载小说/书籍所需的步骤，这些将作为本示例的输入文本进行执行。

# 准备工作

+   将输入数据以`.txt`文件的形式放在工作目录中。

+   输入可以是任何类型的文本，如歌词、小说、杂志文章和源代码。

+   大多数经典文本不再受版权保护，可以免费下载并用于实验。获取免费书籍的最佳途径是 Project [Gutenberg](http://www.gutenberg.org/)。

+   在本章中，我们将使用 Rudyard Kipling 的《丛林之书》作为输入来训练我们的模型，并生成统计上类似的文本作为输出。下面的截图显示了如何以`.txt`格式下载必要的文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00172.jpeg)

+   访问网站并搜索所需的书籍后，点击“Plain Text UTF-8”并下载。UTF-8 基本上指定了编码的类型。可以通过点击链接将文本复制粘贴或直接保存到工作目录中。

# 操作步骤...

在开始之前，先看一下数据并进行分析总是有帮助的。查看数据后，我们可以看到有很多标点符号、空格、引号以及大写和小写字母。在对其进行任何分析或将其馈送到 LSTM 网络之前，我们需要先准备好数据。我们需要一些能够更轻松处理数据的库：

1.  通过以下命令导入必要的库：

```scala
from keras.preprocessing.text import Tokenizer
from keras.utils import to_categorical
from keras.models import Sequential
from keras.layers import Dense, lSTM, Dropout, Embedding
import numpy as np
from pickle import dump
import string
```

1.  前面命令的输出如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00173.jpeg)

1.  始终要仔细检查当前工作目录，并选择所需的文件夹作为工作目录。在我们的案例中，`.txt`文件名为`junglebook.txt`，保存在名为`Chapter 8`的文件夹中。因此，我们将选择该文件夹作为整个章节的工作目录。可以按照下面的截图所示进行操作：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00174.jpeg)

1.  接下来，通过定义一个名为`load_document`的函数将文件加载到程序的内存中，可以通过以下命令完成：

```scala
def load_document(name):
    file = open(name, 'r')
    text = file.read()
    file.close()
    return text
```

1.  使用先前定义的函数将文档加载到内存中，并使用以下脚本打印文本文件的前 2000 个字符：

```scala
input_filename = 'junglebook.txt'
doc = load_document(input_filename)
print(doc[:2000])
```

1.  运行前述函数以及命令会产生如下截屏所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00175.jpeg)

上述代码的输出如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00176.jpeg)

下面的截图是前面输出的延续：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00177.jpeg)

1.  如前面的截图所示，打印了`.txt`文件中的前 2000 个字符。在执行任何预处理之前，始终先分析数据是个好主意。这将更好地指导我们如何进行预处理步骤。

# 工作原理...

1.  `array`函数将用于处理数组形式的数据。`numpy`库提供了这个函数。

1.  由于我们的数据只是文本数据，我们将需要字符串库来处理所有输入数据作为字符串，然后将单词编码为整数，以便进行馈送。

1.  `tokenizer`函数将用于将所有句子拆分为标记，其中每个标记代表一个单词。

1.  pickle 库将被需要，以便使用`dump`函数将字典保存到 pickle 文件中。

1.  `keras`库中的`to_categorical`函数将类向量（整数）转换为二进制类矩阵，例如，用于`categorical_crossentropy`，我们以后将需要将标记映射到唯一整数，反之亦然。

1.  本章中所需的其他 Keras 层包括 LSTM 层、密集层、dropout 层和嵌入层。模型将被顺序定义，因此我们需要`keras`库中的顺序模型。

# 还有更多...

+   您还可以使用相同的模型处理不同类型的文本，例如网站上的客户评论、推文、结构化文本（如源代码、数学理论等）等。

+   本章的目的是了解 LSTM 如何学习长期依赖关系，以及与循环神经网络相比，它们在处理序列数据时表现更好的方式。

+   另一个好主意是将* Pokémon *名称输入模型，并尝试生成自己的* Pokémon *名称。

# 另请参阅

有关使用的不同库的更多信息可以在以下链接找到：

+   [`www.scipy-lectures.org/intro/numpy/array_object.html`](https://www.scipy-lectures.org/intro/numpy/array_object.html)

+   [`docs.python.org/2/library/string.html`](https://docs.python.org/2/library/string.html)

+   [`wiki.python.org/moin/UsingPickle`](https://wiki.python.org/moin/UsingPickle)

+   [`keras.io/preprocessing/text/`](https://keras.io/preprocessing/text/)

+   [`keras.io/layers/core/`](https://keras.io/layers/core/)

+   [`keras.io/layers/recurrent/`](https://keras.io/layers/recurrent/)

# 准备和清理数据

本章的这一部分将讨论在将其作为输入馈送到模型之前涉及的各种数据准备和文本预处理步骤。我们准备数据的具体方式取决于我们打算对其进行建模的方式，这又取决于我们打算如何使用它。

# 准备工作

语言模型将基于统计数据，并预测给定文本输入序列的每个单词的概率。预测的单词将被馈送到模型中，以便生成下一个单词。

一个关键决定是输入序列应该有多长。它们需要足够长，以使模型能够学习单词的上下文以进行预测。此输入长度还将定义用于生成新序列的种子文本的长度，当我们使用模型时。

为了简单起见，我们将任意选择长度为 50 个单词的输入序列长度。

# 如何做...

根据对文本的审查（我们之前做过），以下是可以执行的一些操作，以清理和预处理输入文件中的文本。我们提出了一些关于文本预处理的选项。但是，您可能希望探索更多的清理操作作为练习：

+   用空格替换破折号`–`，以便更好地拆分单词

+   基于空格拆分单词

+   删除输入文本中的所有标点符号，以减少输入模型的文本中唯一字符的数量（例如，Why? 变为 Why）

+   删除所有非字母的单词，以删除独立的标点符号标记和表情符号

+   将所有单词从大写转换为小写，以进一步减少标记的总数并消除任何差异和数据冗余

词汇量是语言建模和决定模型训练时间的决定性因素。较小的词汇量会导致训练速度更快的更高效的模型。在某些情况下，拥有较小的词汇量是有益的，但在其他情况下，拥有较大的词汇量可以防止过拟合。为了预处理数据，我们需要一个函数，它接受整个输入文本，根据空格分割文本，删除所有标点，规范化所有情况，并返回一个标记序列。为此，通过以下命令定义`clean_document`函数：

```scala
 import string
 def clean_document(doc):
     doc = doc.replace('--', ' ')
     tokens = doc.split()
     table = str.maketrans('', '', string.punctuation)
     tokens = [w.translate(table) for w in tokens]
     tokens = [word for word in tokens if word.isalpha()]
     tokens = [word.lower() for word in tokens]
     return tokens
```

1.  先前定义的函数基本上会将加载的文档/文件作为其参数，并返回一个干净的标记数组，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00178.jpeg)

1.  接下来，打印出一些标记和统计数据，以更好地了解`clean_document`函数的作用。通过以下命令完成此步骤：

```scala
tokens = clean_document(doc)
print(tokens[:200])
print('Total Tokens: %d' % len(tokens))
print('Total Unique Tokens: %d' % len(set(tokens)))
```

1.  上述一系列命令的输出打印了前两百个标记，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00179.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00180.jpeg)

1.  接下来，使用以下命令将所有这些标记组织成序列，每个序列包含 50 个单词（任意选择）：

```scala
 length = 50 + 1
 sequences = list()
 for i in range(length, len(tokens)):
     seq = tokens[i-sequence_length:i]
     line = ' '.join(seq)
     sequences.append(line)
 print('Total Sequences: %d' % len(sequences))
```

可以通过打印输出文档形成的序列的总数来查看，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00181.jpeg)

1.  通过以下命令定义`save_doc`函数，将所有生成的标记以及序列保存到工作目录中的文件中：

```scala
def save_document(lines, name):
    data = '\n'.join(lines)
    file = open(name, 'w')
    file.write(data)
    file.close()
```

要保存这些序列，请使用以下两个命令：

```scala
 output_filename = 'junglebook_sequences.txt'
 save_document(sequences, output_filename)
```

1.  该过程如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00182.jpeg)

1.  接下来，加载保存的文档，其中包含所有保存的标记和序列，到内存中使用定义如下的`load_document`函数：

```scala
def load_document(name):
    file = open(name, 'r')
    text = file.read()
    file.close()
    return text

# function to load document and split based on lines
input_filename = 'junglebook_sequences.txt'
doc = load_document(input_filename)
lines = doc.split('\n')
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00183.jpeg)

# 工作原理...

1.  `clean_document`函数删除所有空格、标点、大写文本和引号，并将整个文档分割成标记，其中每个标记都是一个单词。

1.  通过打印文档中的标记总数和唯一标记总数，我们会注意到`clean_document`函数生成了 51,473 个标记，其中 5,027 个标记（或单词）是唯一的。

1.  然后，`save_document`函数保存所有这些标记，以及生成我们每个 50 个单词的序列所需的唯一标记。请注意，通过循环遍历所有生成的标记，我们能够生成一个包含 51,422 个序列的长列表。这些序列将用作训练语言模型的输入。

1.  在对所有 51,422 个序列进行模型训练之前，将标记以及序列保存到文件中始终是一个良好的做法。一旦保存，可以使用定义的`load_document`函数将文件加载回内存。

1.  这些序列组织为 50 个输入标记和一个输出标记（这意味着每个序列有 51 个标记）。为了预测每个输出标记，将使用前 50 个标记作为模型的输入。我们可以通过迭代从第 51 个标记开始的标记列表，并将前 50 个标记作为一个序列，然后重复此过程直到所有标记列表的末尾来实现这一点。

# 另请参阅

访问以下链接，以更好地了解使用各种函数进行数据准备：

+   [`docs.python.org/3/library/tokenize.html`](https://docs.python.org/3/library/tokenize.html)

+   [`keras.io/utils/`](https://keras.io/utils/)

+   [`www.pythonforbeginners.com/dictionary/python-split`](http://www.pythonforbeginners.com/dictionary/python-split)

+   [`www.tutorialspoint.com/python/string_join.htm`](https://www.tutorialspoint.com/python/string_join.htm)

+   [`www.tutorialspoint.com/python/string_lower.htm`](https://www.tutorialspoint.com/python/string_lower.htm)

# 对句子进行标记

在定义和输入数据到 LSTM 网络之前，重要的是将数据转换为神经网络可以理解的形式。计算机理解的一切都是二进制代码（0 和 1），因此，文本或字符串格式的数据需要转换为独热编码变量。

# 准备工作

要了解独热编码的工作原理，请访问以下链接：

+   [`machinelearningmastery.com/how-to-one-hot-encode-sequence-data-in-python/`](https://machinelearningmastery.com/how-to-one-hot-encode-sequence-data-in-python/)

+   [`scikit-learn.org/stable/modules/generated/sklearn.preprocessing.OneHotEncoder.html`](http://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.OneHotEncoder.html)

+   [`stackoverflow.com/questions/37292872/how-can-i-one-hot-encode-in-python`](https://stackoverflow.com/questions/37292872/how-can-i-one-hot-encode-in-python)

+   [`www.ritchieng.com/machinelearning-one-hot-encoding/`](https://www.ritchieng.com/machinelearning-one-hot-encoding/)

+   [`hackernoon.com/what-is-one-hot-encoding-why-and-when-do-you-have-to-use-it-e3c6186d008f`](https://hackernoon.com/what-is-one-hot-encoding-why-and-when-do-you-have-to-use-it-e3c6186d008f)

# 如何做...

经过上一节的学习，您应该能够清理整个语料库并拆分句子。接下来涉及独热编码和标记化句子的步骤可以按以下方式完成：

1.  一旦标记和序列被保存到文件并加载到内存中，它们必须被编码为整数，因为模型中的词嵌入层期望输入序列由整数而不是字符串组成。

1.  这是通过将词汇表中的每个单词映射到唯一的整数并对输入序列进行编码来完成的。稍后，在进行预测时，可以将预测转换（或映射）回数字，以查找它们在相同映射中关联的单词，并从整数到单词的反向映射。

1.  为了执行这种编码，利用 Keras API 中的 Tokenizer 类。在编码之前，必须对整个数据集进行训练，以便找到所有唯一的标记，并为每个标记分配一个唯一的整数。要这样做的命令如下：

```scala
tokenizer = Tokenizer()
tokenizer.fit_on_texts(lines)
sequences = tokenizer.texts_to_sequences(lines)
```

1.  在后面定义嵌入层之前，还需要计算词汇表的大小。这是通过计算映射字典的大小来确定的。

1.  因此，在向嵌入层指定词汇表大小时，将其指定为实际词汇表大小加 1。因此，词汇表大小定义如下：

```scala
vocab_size = len(tokenizer.word_index) + 1
print('Vocabulary size : %d' % vocab_size)
```

1.  现在，一旦输入序列已经被编码，它们需要被分成输入和输出元素，这可以通过数组切片来完成。

1.  分离后，对输出单词进行独热编码。这意味着将其从整数转换为 n 维向量，其中每个词汇表中的单词都有一个 0 值，用 1 表示单词的整数值的索引处的特定单词。Keras 提供了`to_categorical()`函数，可用于为每个输入-输出序列对独热编码输出单词。

1.  最后，指定嵌入层输入序列的长度。我们知道有 50 个单词，因为模型是通过将序列长度指定为 50 来设计的，但指定序列长度的一个好的通用方法是使用输入数据形状的第二维（列数）。

1.  可以通过发出以下命令来完成：

```scala
sequences = array(sequences)
Input, Output = sequences[:,:-1], sequences[:,-1]
Output = to_categorical(Output, num_classes=vocab_size)
sequence_length = Input.shape[1]
```

# 工作原理...

本节将描述在执行上一节中的命令时必须看到的输出：

1.  在对句子进行标记化和计算词汇表长度的命令运行后，您应该看到如下屏幕截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00184.jpeg)

1.  单词被分配值，从 1 开始，直到单词的总数（例如，在这种情况下为 5,027）。嵌入层需要为词汇表中从索引 1 到最大索引的每个单词分配一个向量表示。词汇表末尾的单词的索引将是 5,027；这意味着数组的长度必须是 5,027 + 1。

1.  数组切片和将句子分隔成每个序列 50 个单词的序列后，输出应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00185.jpeg)

1.  使用`to_categorical()`函数，使模型学习预测下一个单词的概率分布。

# 还有更多...

有关在 Python 中重新整形数组的更多信息，请访问以下链接：

+   [`docs.scipy.org/doc/numpy/reference/generated/numpy.reshape.html`](https://docs.scipy.org/doc/numpy/reference/generated/numpy.reshape.html)

+   [`machinelearningmastery.com/index-slice-reshape-numpy-arrays-machine-learning-python/`](https://machinelearningmastery.com/index-slice-reshape-numpy-arrays-machine-learning-python/)

# 训练和保存 LSTM 模型

现在可以从准备好的数据中训练统计语言模型。

将要训练的模型是神经语言模型。它具有一些独特的特点：

+   它使用分布式表示来表示单词，使得具有相似含义的不同单词具有相似的表示

+   它在学习模型的同时学习表示

+   它学会使用前 50 个单词的上下文来预测下一个单词的概率

具体来说，您将使用嵌入层来学习单词的表示，以及**长短期记忆**（**LSTM**）递归神经网络来学习根据上下文预测单词。

# 准备工作

如前所述，学习的嵌入需要知道词汇表的大小和输入序列的长度。它还有一个参数，用于指定将用于表示每个单词的维度的数量。这就是嵌入向量空间的大小。

常见值为 50、100 和 300。我们将在这里使用 100，但考虑测试更小或更大的值，并评估这些值的指标。

网络将由以下组成：

+   两个具有 200 个记忆单元的 LSTM 隐藏层。更多的记忆单元和更深的网络可能会取得更好的结果。

+   一个 dropout 层，dropout 率为 0.3 或 30%，这将帮助网络减少对每个神经元/单元的依赖，并减少过拟合数据。

+   一个具有 200 个神经元的全连接层连接到 LSTM 隐藏层，以解释从序列中提取的特征。

+   输出层预测下一个单词，作为词汇表大小的单个向量，其中每个单词在词汇表中都有一个概率。

+   在第二个密集或全连接层中使用 softmax 分类器，以确保输出具有归一化概率的特性（例如在 0 和 1 之间）。

# 如何做...

1.  使用以下命令定义模型，并在以下截图中进行说明：

```scala
model = Sequential()
model.add(Embedding(vocab_size, 100, input_length=sequence_length))
model.add(LSTM(200, return_sequences=True))
model.add(LSTM(200))
model.add(Dropout(0.3))
model.add(Dense(200, activation='relu'))
model.add(Dense(vocab_size, activation='softmax'))
print(model.summary())
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00186.jpeg)

1.  打印模型摘要，以确保模型按预期构建。

1.  编译模型，指定需要拟合模型的分类交叉熵损失。将 epochs 数设置为 75，并使用批量大小为 250 的小批量训练模型。使用以下命令完成：

```scala
 model.compile(loss='categorical_crossentropy', optimizer='adam', 
        metrics=['accuracy'])

 model.fit(Input, Output, batch_size=250, epochs=75)
```

1.  上述命令的输出在以下截图中进行说明：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00187.jpeg)

1.  模型编译完成后，使用以下命令保存：

```scala
model.save('junglebook_trained.h5')

dump(tokenizer, open('tokenizer.pkl', 'wb'))
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00188.jpeg)

# 它是如何工作的...

1.  模型是使用 Keras 框架中的`Sequential()`函数构建的。模型中的第一层是一个嵌入层，它以词汇量、向量维度和输入序列长度作为参数。

1.  接下来的两层是每个具有 200 个内存单元的 LSTM 层。可以尝试使用更多内存单元和更深的网络来检查是否可以提高准确性。

1.  接下来的一层是一个丢弃层，丢弃概率为 30%，这意味着在训练过程中某个记忆单元不被使用的概率为 30%。这可以防止数据过拟合。同样，可以调整和调优丢弃概率。

1.  最后两层是两个全连接层。第一个具有`relu`激活函数，第二个具有 softmax 分类器。打印模型摘要以检查模型是否按要求构建。

1.  请注意，在这种情况下，可训练参数的总数为 2,115,228。模型摘要还显示了模型中每个层将被训练的参数数量。

1.  在我们的案例中，模型是在 75 个时期的小批量中训练的，以最小化训练时间。将时期数增加到 100 以上，并在训练时使用更小的批量，可以大大提高模型的准确性，同时减少损失。

1.  在训练过程中，您将看到性能摘要，包括每个批次更新结束时从训练数据评估的损失和准确性。在我们的案例中，运行了 75 个时期后，我们获得了接近 40%的准确性。

1.  模型的目标不是以 100%的准确性记住文本，而是捕捉输入文本的属性，如自然语言和句子中存在的长期依赖关系和结构。

1.  在训练完成后，模型将保存在名为`junglebook_trained.h5`的工作目录中。

1.  当模型稍后加载到内存中进行预测时，我们还需要单词到整数的映射。这在`Tokenizer`对象中存在，并且也使用`Pickle`库中的`dump()`函数保存。

# 还有更多...

Jason Brownlee 在 Machine Learning Mastery 的博客上有很多关于开发、训练和调整自然语言处理机器学习模型的有用信息。可以在以下链接找到：

[`machinelearningmastery.com/deep-learning-for-nlp/`](https://machinelearningmastery.com/deep-learning-for-nlp/)

[`machinelearningmastery.com/lstms-with-python/`](https://machinelearningmastery.com/lstms-with-python/)

[`machinelearningmastery.com/blog/`](https://machinelearningmastery.com/deep-learning-for-nlp/)

# 另请参阅

有关本节中使用的不同 keras 层和其他函数的更多信息可以在以下链接找到：

+   [`keras.io/models/sequential/`](https://keras.io/models/sequential/)

+   [`docs.python.org/2/library/pickle.html`](https://docs.python.org/2/library/pickle.html)

+   [`keras.io/optimizers/`](https://keras.io/optimizers/)

+   [`keras.io/models/model/`](https://keras.io/models/model/)

# 使用模型生成类似的文本

现在您有了一个经过训练的语言模型，可以使用它。在这种情况下，您可以使用它来生成具有与源文本相同统计特性的新文本序列。至少对于这个例子来说，这并不实际，但它给出了语言模型学到了什么的一个具体例子。

# 准备工作

1.  首先重新加载训练序列。您可以使用我们最初开发的`load_document()`函数来实现。通过以下代码实现：

```scala
def load_document(name):
    file = open(name, 'r')
    text = file.read()
    file.close()
    return text

# load sequences of cleaned text
input_filename = 'junglebook_sequences.txt'
doc = load_document(input_filename)
lines = doc.split('\n')
```

上述代码的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00189.jpeg)

1.  请注意，输入文件名现在是`'junglebook_sequences.txt'`，这将把保存的训练序列加载到内存中。我们需要文本，以便我们可以选择一个源序列作为模型的输入，以生成新的文本序列。

1.  模型将需要 50 个单词作为输入。

随后，需要指定输入的预期长度。这可以通过计算加载的数据的一行的长度并减去 1 来从输入序列中确定，因为预期的输出单词也在同一行上，如下所示：

`sequence_length = len(lines[0].split()) - 1`

1.  接下来，通过执行以下命令将训练和保存的模型加载到内存中：

```scala
 from keras.models import load_model
 model = load_model('junglebook.h5')
```

1.  生成文本的第一步是准备种子输入。为此目的，从输入文本中随机选择一行文本。一旦选择，打印它以便您对使用的内容有一些了解。操作如下：

```scala
from random import randint
seed_text = lines[randint(0,len(lines))]
print(seed_text + '\n')
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00190.jpeg)

# 如何做...

1.  现在，您可以逐个生成新单词。首先，使用训练模型时使用的相同标记器将种子文本编码为整数，操作如下：

`encoded = tokenizer.texts_to_sequences([seed_text])[0]`

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00191.jpeg)

1.  模型可以通过调用`model.predict_classes()`直接预测下一个单词，这将返回具有最高概率的单词的索引：

```scala
 prediction = model.predict_classes(encoded, verbose=0)

```

1.  查找标记器映射中的索引以获取相关联的单词，如下所示：

```scala
 out_word = ''
 for word, index in tokenizer.word_index.items():
         if index == prediction:
                 out_word = word
                 break
```

1.  将这个单词附加到种子文本中并重复这个过程。重要的是，输入序列将变得太长。在将输入序列编码为整数后，我们可以将其截断为所需的长度。Keras 提供了`pad_sequences()`函数，我们可以使用它来执行这种截断，如下所示：

```scala
 encoded = pad_sequences([encoded], maxlen=seq_length, truncating='pre')

```

1.  将所有这些封装到一个名为`generate_sequence()`的函数中，该函数以模型、标记器、输入序列长度、种子文本和要生成的单词数量作为输入。然后，它返回模型生成的一系列单词。您可以使用以下代码来实现：

```scala
 from random import randint
 from pickle import load
 from keras.models import load_model
 from keras.preprocessing.sequence import pad_sequences

 def load_document(filename):
     file = open(filename, 'r')
     text = file.read()
     file.close()
     return text

 def generate_sequence(model, tokenizer, sequence_length, seed_text, n_words):
     result = list()
     input_text = seed_text
     for _ in range(n_words):
         encoded = tokenizer.texts_to_sequences([input_text])[0]
         encoded = pad_sequences([encoded], maxlen=seq_length,                 truncating='pre')
         prediction = model.predict_classes(encoded, verbose=0)
         out_word = ''
             for word, index in tokenizer.word_index.items():
                 if index == prediction:
                     out_word = word
                     break
      input_text += ' ' + out_word
      result.append(out_word)
    return ' '.join(result)

 input_filename = 'junglebook_sequences.txt'
 doc = load_document(input_filename)
 lines = doc.split('\n')
 seq_length = len(lines[0].split()) - 1
```

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00192.jpeg)

# 工作原理...

现在，我们准备生成一系列新单词，假设我们有一些种子文本：

1.  首先使用以下命令将模型重新加载到内存中：

```scala
 model = load_model('junglebook.h5')
```

1.  接下来，通过输入以下命令加载标记器：

```scala
 tokenizer = load(open('tokenizer.pkl', 'rb'))
```

1.  通过使用以下命令随机选择一个种子文本：

```scala
 seed_text = lines[randint(0,len(lines))]
 print(seed_text + '\n')
```

1.  最后，通过使用以下命令生成一个新序列：

```scala
 generated = generate_sequence(model, tokenizer, sequence_length,             seed_text, 50)
 print(generated)
```

1.  在打印生成的序列时，您将看到类似于以下屏幕截图的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00193.jpeg)

1.  模型首先打印随机种子文本的 50 个单词，然后打印生成文本的 50 个单词。在这种情况下，随机种子文本如下：

*篮子里装满了干草，放入蚱蜢，或者捉两只螳螂让它们打架，或者串一串红色和黑色的丛林果仁做成项链，或者看蜥蜴在岩石上晒太阳，或者蛇在泥坑附近捕捉青蛙，然后它们唱着长长的歌*

在这种情况下，模型生成的 50 个单词如下：

*在评论结束时有奇怪的本地颤音，他看到的鬣狗，他们感到被拉到他周围的噪音，为了峡谷末端的画面，嗅着被咬的和最好的公牛在黎明时是本地人*

1.  请注意模型输出了一系列随机单词，这些单词是根据它从输入文本中学到的内容生成的。您还会注意到，模型在模仿输入文本并生成自己的故事方面做得相当不错。尽管文本没有太多意义，但它为我们提供了宝贵的见解，即模型如何学习将统计上相似的单词放在一起。

# 还有更多...

+   更改设置的随机种子后，网络生成的输出也会发生变化。您可能无法获得与前面示例完全相同的输出文本，但它将与用于训练模型的输入非常相似。

+   以下是通过多次运行生成文本片段获得的不同结果的一些屏幕截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00194.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00195.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00196.jpeg)

+   模型甚至生成了自己版本的项目古腾堡许可证，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00197.jpeg)

+   模型的准确性可以通过将时代数量从大约 100 增加到 200 来提高到约 60％。另一种增加学习的方法是通过以大约 50 和 100 的小批量训练模型。尝试玩弄不同的超参数和激活函数，以查看以最佳方式影响结果的方法。

+   还可以通过在定义模型时包含更多的 LSTM 和丢失层来使模型更加密集。但是，请注意，如果模型更复杂并且运行的时代更长，它只会增加训练时间。

+   经过大量实验，发现理想的批处理大小在 50 到 100 之间，并且确定了训练模型的理想时代数量在 100 到 200 之间。

+   执行前述任务的确切方法并不存在。您还可以尝试使用不同的文本输入到模型，例如推文，客户评论或 HTML 代码。

+   还可以执行一些其他任务，包括使用简化的词汇表（例如删除所有停用词）以进一步增强字典中的唯一单词；调整嵌入层的大小和隐藏层中的记忆单元数量；并扩展模型以使用预训练模型，例如 Google 的 Word2Vec（预训练词模型），以查看是否会产生更好的模型。

# 另请参阅

有关本章最后一节中使用的各种函数和库的更多信息，请访问以下链接：

+   [`keras.io/preprocessing/sequence/`](https://keras.io/preprocessing/sequence/)

+   [`wiki.python.org/moin/UsingPickle`](https://wiki.python.org/moin/UsingPickle)

+   [`docs.python.org/2/library/random.html`](https://docs.python.org/2/library/random.html)

+   [`www.tensorflow.org/api_docs/python/tf/keras/models/load_model`](https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model)


# 第七章：使用 TF-IDF 进行自然语言处理

在本章中，将涵盖以下内容：

+   下载治疗机器人会话文本数据集

+   分析治疗机器人会话数据集

+   可视化数据集中的词频

+   计算文本的情感分析

+   从文本中删除停用词

+   训练 TF-IDF 模型

+   评估 TF-IDF 模型性能

+   将模型性能与基准分数进行比较

# 介绍

自然语言处理（NLP）最近成为新闻的焦点，如果你问五个不同的人，你会得到十个不同的定义。最近，NLP 已被用于帮助识别互联网上试图传播假新闻或更糟的是欺凌行为的机器人或喷子。事实上，最近在西班牙发生了一起案件，一所学校的学生通过社交媒体账户遭到网络欺凌，这对学生的健康产生了严重影响，老师们开始介入。学校联系了研究人员，他们能够帮助识别使用 TF-IDF 等 NLP 方法的潜在喷子。最终，潜在的学生名单被提交给学校，当面对时，实际嫌疑人承认了自己的行为。这个故事发表在一篇名为《Twitter 社交网络中喷子档案检测的监督机器学习：网络欺凌的真实案例应用》的论文中，作者是 Patxi Galan-Garcıa、Jose Gaviria de la Puerta、Carlos Laorden Gomez、Igor Santos 和 Pablo Garcıa Bringas。

本文重点介绍了利用多种不同方法分析文本和开发类似人类语言处理的能力。正是这种方法将自然语言处理（NLP）融入到机器学习、深度学习和人工智能中。让机器能够摄取文本数据并可能从同样的文本数据中做出决策是自然语言处理的核心。有许多用于 NLP 的算法，例如以下内容：

+   TF-IDF

+   Word2Vec

+   N-gram

+   潜在狄利克雷分配（LDA）

+   长短期记忆（LSTM）

本章将专注于一个包含个人与在线治疗网站聊天机器人之间对话的数据集。聊天机器人的目的是识别需要立即引起个人关注而不是继续与聊天机器人讨论的对话。最终，我们将专注于使用 TF-IDF 算法对数据集进行文本分析，以确定聊天对话是否需要被升级到个人的分类。TF-IDF 代表词项频率-逆文档频率。这是一种常用的算法技术，用于识别文档中单词的重要性。此外，TF-IDF 在处理文档中的高词频时易于计算，并且能够衡量单词的独特性。在处理聊天机器人数据时，这非常有用。主要目标是快速识别一个唯一的单词，触发升级到个人以提供即时支持。

# 下载治疗机器人会话文本数据集

本节将重点介绍下载和设置本章中用于 NLP 的数据集。

# 准备工作

本章将使用基于治疗机器人与在线治疗网站访客之间的互动的数据集。它包含 100 个互动，每个互动都被标记为“升级”或“不升级”。如果讨论需要更严肃的对话，机器人将会将讨论标记为“升级”给个人。否则，机器人将继续与用户讨论。

# 它是如何工作的...

本节将介绍下载聊天机器人数据的步骤。

1.  从以下 GitHub 存储库访问数据集：[`github.com/asherif844/ApacheSparkDeepLearningCookbook/tree/master/CH07/data`](https://github.com/asherif844/ApacheSparkDeepLearningCookbook/tree/master/CH07/data)

1.  一旦您到达存储库，右键单击以下截图中看到的文件：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00198.jpeg)

1.  下载 `TherapyBotSession.csv` 并保存到与 Jupyter 笔记本 `SparkSession` 相同的本地目录中。

1.  通过以下脚本在 Jupyter 笔记本中访问数据集，构建名为 `spark` 的 `SparkSession`，并将数据集分配给 Spark 中的数据框 `df`：

```scala
spark = SparkSession.builder \
        .master("local") \
        .appName("Natural Language Processing") \
        .config("spark.executor.memory", "6gb") \
        .getOrCreate()
df = spark.read.format('com.databricks.spark.csv')\
     .options(header='true', inferschema='true')\
     .load('TherapyBotSession.csv')  
```

# 如何做...

本节解释了聊天机器人数据如何进入我们的 Jupyter 笔记本。

1.  数据集的内容可以通过点击存储库中的 TherapyBotSession.csv 查看，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00199.jpeg)

1.  一旦数据集被下载，它可以被上传并转换为一个名为 `df` 的数据框。可以通过执行 `df.show()` 来查看数据框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00200.jpeg)

1.  有 3 个主要字段对我们来说特别感兴趣：

1.  `id`：网站访问者和聊天机器人之间每笔交易的唯一标识。

1.  `label`：由于这是一种监督建模方法，我们知道我们要预测的结果，每个交易都被分类为 `escalate` 或 `do_not_escalate`。在建模过程中，将使用该字段来训练文本以识别属于这两种情况之一的单词。

1.  `chat`：最后我们有来自网站访问者的 `chat` 文本，我们的模型将对其进行分类。

# 还有更多...

数据框 `df` 还有一些额外的列 `_c3`、`_c4`、`_c5` 和 `_c6`，这些列将不会在模型中使用，因此可以使用以下脚本从数据集中排除。

```scala
df = df.select('id', 'label', 'chat')
df.show()
```

脚本的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00201.jpeg)

# 分析治疗机器人会话数据

在应用模型之前，始终先分析任何数据集是很重要的

# 准备工作

这一部分将需要从 `pyspark.sql` 导入 `functions` 来在我们的数据框上执行。

```scala
import pyspark.sql.functions as F
```

# 如何做...

以下部分将介绍对文本数据进行分析的步骤。

1.  执行以下脚本来对 `label` 列进行分组并生成计数分布：

```scala
df.groupBy("label") \
   .count() \
   .orderBy("count", ascending = False) \
   .show()
```

1.  使用以下脚本向数据框 `df` 添加一个新列 `word_count`：

```scala
import pyspark.sql.functions as F
df = df.withColumn('word_count', F.size(F.split(F.col('response_text'),' ')))
```

1.  使用以下脚本按 `label` 聚合平均单词计数 `avg_word_count`：

```scala
df.groupBy('label')\
  .agg(F.avg('word_count').alias('avg_word_count'))\
  .orderBy('avg_word_count', ascending = False) \
  .show()
```

# 它是如何工作的...

以下部分解释了分析文本数据所获得的反馈。

1.  收集跨多行的数据并按维度对结果进行分组是很有用的。在这种情况下，维度是 `label`。使用 `df.groupby()` 函数来测量按 `label` 分布的 100 笔在线治疗交易的计数。我们可以看到 `do_not_escalate` 到 `escalate` 的分布是 `65`：`35`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00202.jpeg)

1.  创建一个新列 `word_count`，用于计算聊天机器人和在线访问者之间的 100 笔交易中每笔交易使用了多少单词。新创建的列 `word_count` 可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00203.jpeg)

1.  由于现在在数据框中添加了 `word_count`，可以对其进行聚合以计算按 `label` 的平均单词计数。一旦执行了这个操作，我们可以看到 `escalate` 对话的平均长度是 `do_not_escalate` 对话的两倍多，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00204.jpeg)

# 可视化数据集中的单词计数

一张图片胜过千言万语，本节将证明这一点。不幸的是，截至版本 2.2，Spark 没有任何内在的绘图能力。为了在数据框中绘制值，我们必须转换为 `pandas`。

# 准备工作

本节将需要导入`matplotlib`进行绘图：

```scala
import matplotlib.pyplot as plt
%matplotlib inline
```

# 如何做...

本节将介绍将 Spark 数据框转换为可以在 Jupyter 笔记本中查看的可视化的步骤。

1.  使用以下脚本将 Spark 数据框转换为`pandas`数据框：

```scala
df_plot = df.select('id', 'word_count').toPandas()
```

1.  使用以下脚本绘制数据框：

```scala
import matplotlib.pyplot as plt
%matplotlib inline

df_plot.set_index('id', inplace=True)
df_plot.plot(kind='bar', figsize=(16, 6))
plt.ylabel('Word Count')
plt.title('Word Count distribution')
plt.show()
```

# 工作原理...

本节解释了如何将 Spark 数据框转换为`pandas`，然后绘制。

1.  从 Spark 中收集数据框的子集，并使用 Spark 中的`toPandas()`方法转换为`pandas`。

1.  然后使用 matplotlib 绘制数据的子集，将 y 值设置为`word_count`，将 x 值设置为`id`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00205.jpeg)

# 另请参阅

Python 中除了`matplotlib`之外还有其他绘图功能，例如`bokeh`、`plotly`和`seaborn`。

要了解有关`bokeh`的更多信息，请访问以下网站：

[`bokeh.pydata.org/en/latest/`](https://bokeh.pydata.org/en/latest/)

要了解有关`plotly`的更多信息，请访问以下网站：

[`plot.ly/`](https://plot.ly/)

要了解有关`seaborn`的更多信息，请访问以下网站：

[`seaborn.pydata.org/`](https://seaborn.pydata.org/)

# 计算文本的情感分析

情感分析是从单词或一系列单词中推导出语气和感觉的能力。本节将利用 Python 技术从数据集中的 100 个交易中计算情感分析分数。

# 准备工作

本节将需要在 PySpark 中使用函数和数据类型。此外，我们还将导入`TextBlob`库进行情感分析。为了在 PySpark 中使用 SQL 和数据类型函数，必须导入以下内容：

```scala
from pyspark.sql.types import FloatType 
```

此外，为了使用`TextBlob`，必须导入以下库：

```scala
from textblob import TextBlob
```

# 如何做...

以下部分将介绍将情感分数应用于数据集的步骤。

1.  使用以下脚本创建情感分数函数`sentiment_score`：

```scala
from textblob import TextBlob
def sentiment_score(chat):
    return TextBlob(chat).sentiment.polarity
```

1.  使用以下脚本在数据框中的每个对话响应上应用`sentiment_score`：

1.  创建一个名为`sentiment_score_udf`的`lambda`函数，将`sentiment_score`映射到 Spark 中的用户定义函数`udf`，并指定`FloatType()`的输出类型，如下脚本所示：

```scala
from pyspark.sql.types import FloatType
sentiment_score_udf = F.udf(lambda x: sentiment_score(x), FloatType())
```

1.  在数据框中的每个`chat`列上应用函数`sentiment_score_udf`，如下脚本所示：

```scala
df = df.select('id', 'label', 'chat','word_count',
                   sentiment_score_udf('chat').alias('sentiment_score'))
```

1.  使用以下脚本计算按`label`分组的平均情感分数`avg_sentiment_score`：

```scala
df.groupBy('label')\
     .agg(F.avg('sentiment_score').alias('avg_sentiment_score'))\
     .orderBy('avg_sentiment_score', ascending = False) \
     .show()
```

# 工作原理...

本节解释了如何将 Python 函数转换为 Spark 中的用户定义函数`udf`，以将情感分析分数应用于数据框中的每一列。

1.  `Textblob`是 Python 中的情感分析库。它可以从名为`sentiment.polarity`的方法中计算情感分数，该方法的得分范围为-1（非常负面）到+1（非常正面），0 为中性。此外，`Textblob`还可以从 0（非常客观）到 1（非常主观）测量主观性；尽管在本章中我们不会测量主观性。

1.  将 Python 函数应用于 Spark 数据框有几个步骤：

1.  导入`Textblob`并将名为`sentiment_score`的函数应用于`chat`列，以生成每个机器人对话的情感极性，并在新列中生成情感分数，也称为`sentiment_score`。

1.  Python 函数不能直接应用于 Spark 数据框，而必须先经过用户定义函数转换`udf`，然后在 Spark 中应用。

1.  此外，函数的输出也必须明确说明，无论是整数还是浮点数据类型。在我们的情况下，我们明确说明函数的输出将使用`FloatType() from pyspark.sql.types`。最后，使用`udf`情感分数函数内的`lambda`函数在每行上应用情感。

1.  通过执行`df.show()`，可以看到具有新创建字段`情感分数`的更新后的数据框，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00206.jpeg)

1.  现在，对于聊天对话中的每个响应计算了`sentiment_score`之后，我们可以为每行指定-1（非常负面的极性）到+1（非常正面的极性）的值范围。就像我们对计数和平均词数所做的那样，我们可以比较`升级`对话在情感上是否比`不升级`对话更积极或更消极。我们可以通过`label`计算平均情感分数`avg_sentiment_score`，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00207.jpeg)

1.  最初，假设`升级`对话的极性得分会比`不升级`更负面是有道理的。实际上，我们发现`升级`在极性上比`不升级`稍微更积极；但是，两者都相当中性，因为它们接近 0。

# 另请参阅

要了解有关`TextBlob`库的更多信息，请访问以下网站：

[`textblob.readthedocs.io/en/dev/`](http://textblob.readthedocs.io/en/dev/)

# 从文本中删除停用词

停用词是英语中非常常见的单词，通常会从常见的 NLP 技术中删除，因为它们可能会分散注意力。常见的停用词可能是诸如*the*或*and*之类的单词。

# 准备工作

本节需要导入以下库：

```scala
from pyspark.ml.feature import StopWordsRemover 
from pyspark.ml import Pipeline
```

# 操作步骤...

本节介绍了删除停用词的步骤。

1.  执行以下脚本，将`chat`中的每个单词提取为数组中的字符串：

```scala
df = df.withColumn('words',F.split(F.col('chat'),' '))
```

1.  使用以下脚本将一组常见单词分配给变量`stop_words`，这些单词将被视为停用词：

```scala
stop_words = ['i','me','my','myself','we','our','ours','ourselves',
'you','your','yours','yourself','yourselves','he','him',
'his','himself','she','her','hers','herself','it','its',
'itself','they','them','their','theirs','themselves',
'what','which','who','whom','this','that','these','those',
'am','is','are','was','were','be','been','being','have',
'has','had','having','do','does','did','doing','a','an',
'the','and','but','if','or','because','as','until','while',
'of','at','by','for','with','about','against','between',
'into','through','during','before','after','above','below',
'to','from','up','down','in','out','on','off','over','under',
'again','further','then','once','here','there','when','where',
'why','how','all','any','both','each','few','more','most',
'other','some','such','no','nor','not','only','own','same',
'so','than','too','very','can','will','just','don','should','now']
```

1.  执行以下脚本，从 PySpark 导入`StopWordsRemover`函数，并配置输入和输出列`words`和`word without stop`：

```scala
from pyspark.ml.feature import StopWordsRemover 

stopwordsRemovalFeature = StopWordsRemover(inputCol="words", 
                   outputCol="words without stop").setStopWords(stop_words)
```

1.  执行以下脚本以导入 Pipeline 并为将应用于数据框的停用词转换过程定义`stages`：

```scala
from pyspark.ml import Pipeline

stopWordRemovalPipeline = Pipeline(stages=[stopwordsRemovalFeature])
pipelineFitRemoveStopWords = stopWordRemovalPipeline.fit(df)
```

1.  最后，使用以下脚本将停用词移除转换`pipelineFitRemoveStopWords`应用于数据框`df`：

```scala
df = pipelineFitRemoveStopWords.transform(df)
```

# 工作原理...

本节解释了如何从文本中删除停用词。

1.  就像我们在对`chat`数据进行分析时一样，我们也可以调整`chat`对话的文本，并将每个单词分解为单独的数组。这将用于隔离停用词并将其删除。

1.  将每个单词提取为字符串的新列称为`words`，可以在以下截屏中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00208.jpeg)

1.  有许多方法可以将一组单词分配给停用词列表。其中一些单词可以使用适当的 Python 库`nltk`（自然语言工具包）自动下载和更新。对于我们的目的，我们将利用一个常见的 124 个停用词列表来生成我们自己的列表。可以轻松地手动添加或从列表中删除其他单词。

1.  停用词不会为文本增添任何价值，并且将通过指定`outputCol="words without stop"`从新创建的列中删除。此外，通过指定`inputCol = "words"`来设置将用作转换源的列。

1.  我们创建一个管道，`stopWordRemovalPipeline`，来定义将转换数据的步骤或`阶段`的顺序。在这种情况下，唯一用于转换数据的阶段是特征`stopwordsRemover`。

1.  管道中的每个阶段都可以具有转换角色和估计角色。估计角色`pipeline.fit(df)`用于生成名为`pipelineFitRemoveStopWords`的转换器函数。最后，在数据框上调用`transform(df)`函数，以生成具有名为`words without stop`的新列的更新后的数据框。我们可以将两列并排比较以查看差异，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00209.jpeg)

1.  新列`words without stop`不包含原始列`words`中被视为停用词的任何字符串。

# 另请参阅

要了解有关`nltk`的停用词的更多信息，请访问以下网站：

[`www.nltk.org/data.html`](https://www.nltk.org/data.html)

要了解更多关于 Spark 机器学习管道的信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/ml-pipeline.html`](https://spark.apache.org/docs/2.2.0/ml-pipeline.html)

要了解 PySpark 中`StopWordsRemover`功能的更多信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/api/python/pyspark.ml.html#pyspark.ml.feature.StopWordsRemover`](https://spark.apache.org/docs/2.2.0/api/python/pyspark.ml.html#pyspark.ml.feature.StopWordsRemover)

# 训练 TF-IDF 模型

我们现在准备训练我们的 TF-IDF NLP 模型，并查看是否可以将这些交易分类为`升级`或`不升级`。

# 准备工作

本节将需要从`spark.ml.feature`和`spark.ml.classification`导入。

# 操作步骤...

以下部分将逐步介绍训练 TF-IDF 模型的步骤。

1.  创建一个新的用户定义函数`udf`，使用以下脚本为`label`列定义数值：

```scala
label = F.udf(lambda x: 1.0 if x == 'escalate' else 0.0, FloatType())
df = df.withColumn('label', label('label'))
```

1.  执行以下脚本以设置单词向量化的 TF 和 IDF 列：

```scala
import pyspark.ml.feature as feat
TF_ = feat.HashingTF(inputCol="words without stop", 
                     outputCol="rawFeatures", numFeatures=100000)
IDF_ = feat.IDF(inputCol="rawFeatures", outputCol="features")
```

1.  使用以下脚本设置管道`pipelineTFIDF`，以设置`TF_`和`IDF_`的阶段顺序：

```scala
pipelineTFIDF = Pipeline(stages=[TF_, IDF_])
```

1.  使用以下脚本将 IDF 估计器拟合到数据框`df`上：

```scala
pipelineFit = pipelineTFIDF.fit(df)
df = pipelineFit.transform(df)
```

1.  使用以下脚本将数据框拆分为 75:25 的比例，用于模型评估目的：

```scala
(trainingDF, testDF) = df.randomSplit([0.75, 0.25], seed = 1234)
```

1.  使用以下脚本导入和配置分类模型`LogisticRegression`：

```scala
from pyspark.ml.classification import LogisticRegression
logreg = LogisticRegression(regParam=0.25)
```

1.  将逻辑回归模型`logreg`拟合到训练数据框`trainingDF`上。基于逻辑回归模型的`transform()`方法，创建一个新的数据框`predictionDF`，如下脚本所示：

```scala
logregModel = logreg.fit(trainingDF)
predictionDF = logregModel.transform(testDF)
```

# 工作原理...

以下部分解释了如何有效地训练 TF-IDF NLP 模型。

1.  最好将标签以数值格式而不是分类形式呈现，因为模型能够在将输出分类为 0 和 1 之间时解释数值。因此，`label`列下的所有标签都转换为 0.0 或 1.0 的数值`label`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00210.jpeg)

1.  TF-IDF 模型需要通过从`pyspark.ml.feature`导入`HashingTF`和`IDF`来进行两步处理，以处理不同的任务。第一个任务仅涉及导入`HashingTF`和`IDF`并为输入和随后的输出列分配值。`numfeatures`参数设置为 100,000，以确保它大于数据框中单词的不同数量。如果`numfeatures`小于不同的单词计数，模型将不准确。

1.  如前所述，管道的每个步骤都包含一个转换过程和一个估计器过程。管道`pipelineTFIDF`被配置为按顺序排列步骤，其中`IDF`将跟随`HashingTF`。

1.  `HashingTF`用于将`words without stop`转换为新列`rawFeatures`中的向量。随后，`rawFeatures`将被`IDF`消耗，以估算大小并适应数据框以生成名为`features`的新列，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00211.jpeg)

1.  为了培训目的，我们的数据框将以`75`:`25`的比例保守地拆分，随机种子设置为`1234`。

1.  由于我们的主要目标是将每个对话分类为`升级`以进行升级或`不升级`以进行继续的机器人聊天，因此我们可以使用 PySpark 库中的传统分类算法，如逻辑回归模型。逻辑回归模型配置了正则化参数`regParam`为 0.025。我们使用该参数略微改进模型，以最小化过度拟合，代价是略微偏差。

1.  逻辑回归模型在`trainingDF`上进行训练和拟合，然后创建一个新的数据框`predictionDF`，其中包含新转换的字段`prediction`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00212.jpeg)

# 还有更多...

虽然我们确实使用了用户定义的函数`udf`来手动创建一个数值标签列，但我们也可以使用 PySpark 的内置功能`StringIndexer`来为分类标签分配数值。要查看`StringIndexer`的操作，请访问第五章，*使用 Spark ML 预测消防部门呼叫*。

# 另请参阅

要了解有关 PySpark 中 TF-IDF 模型的更多信息，请访问以下网站：

[`spark.apache.org/docs/latest/mllib-feature-extraction.html#tf-idf`](https://spark.apache.org/docs/latest/mllib-feature-extraction.html#tf-idf)

# 评估 TF-IDF 模型性能

此时，我们已准备好评估我们模型的性能

# 准备工作

本节将需要导入以下库：

+   来自`sklearn`的`metrics`

+   `pyspark.ml.evaluation`中的`BinaryClassificationEvaluator`

# 如何做...

本节介绍了评估 TF-IDF NLP 模型的步骤。

1.  使用以下脚本创建混淆矩阵：

```scala
predictionDF.crosstab('label', 'prediction').show()
```

1.  使用以下脚本从`sklearn`评估模型的`metrics`：

```scala
from sklearn import metrics

actual = predictionDF.select('label').toPandas()
predicted = predictionDF.select('prediction').toPandas()
print('accuracy score: {}%'.format(round(metrics.accuracy_score(actual,         predicted),3)*100))
```

1.  使用以下脚本计算 ROC 分数：

```scala
from pyspark.ml.evaluation import BinaryClassificationEvaluator

scores = predictionDF.select('label', 'rawPrediction')
evaluator = BinaryClassificationEvaluator()
print('The ROC score is {}%'.format(round(evaluator.evaluate(scores),3)*100))
```

# 它是如何工作的...

本节解释了我们如何使用评估计算来确定模型的准确性。

1.  混淆矩阵有助于快速总结实际结果和预测结果之间的准确性数字。由于我们有 75:25 的分割，我们应该从训练数据集中看到 25 个预测。我们可以使用以下脚本构建混淆矩阵：`predictionDF.crosstab('label', 'prediction').show()`。脚本的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00213.jpeg)

1.  我们现在处于通过比较`prediction`值和实际`label`值来评估模型准确度的阶段。`sklearn.metrics`接受两个参数，与`label`列相关联的`actual`值，以及从逻辑回归模型派生的`predicted`值。

请注意，我们再次将 Spark 数据框的列值转换为 pandas 数据框，使用`toPandas()`方法。

1.  创建了两个变量`actual`和`predicted`，并使用`metrics.accuracy_score()`函数计算了 91.7%的准确度分数，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00214.jpeg)

1.  ROC（接收器操作特性）通常与测量真正率相对于假正率的曲线相关联。曲线下面积越大，越好。与曲线相关的 ROC 分数是另一个指标，可用于衡量模型的性能。我们可以使用`BinaryClassificationEvaluator`计算`ROC`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00215.jpeg)

# 另请参阅

要了解有关 PySpark 中的`BinaryClassificationEvaluator`的更多信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/api/java/index.html?org/apache/spark/ml/evaluation/BinaryClassificationEvaluator.html`](https://spark.apache.org/docs/2.2.0/api/java/index.html?org/apache/spark/ml/evaluation/BinaryClassificationEvaluator.html)

# 将模型性能与基线分数进行比较

虽然我们的模型具有 91.7%的高准确度分数，这很好，但将其与基线分数进行比较也很重要。我们在本节中深入探讨了这个概念。

# 如何做...

本节介绍了计算基线准确度的步骤。

1.  执行以下脚本以从`describe()`方法中检索平均值：

```scala
predictionDF.describe('label').show()
```

1.  减去`1-平均值分数`以计算基线准确度。

# 它是如何工作的...

本节解释了基线准确度背后的概念，以及我们如何使用它来理解模型的有效性。

1.  如果每个`chat`对话都被标记为`do_not_escalate`或反之亦然，我们是否会有高于 91.7％的基准准确率？找出这一点最简单的方法是使用以下脚本在`predictionDF`的`label`列上运行`describe()`方法：`predictionDF.describe('label').show()`

1.  可以在以下截图中看到脚本的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00216.jpeg)

1.  `label`的平均值为 0.2083 或约 21％，这意味着`label`为 1 的情况仅发生了 21％的时间。因此，如果我们将每个对话标记为`do_not_escalate`，我们将有大约 79％的准确率，这低于我们的模型准确率 91.7％。

1.  因此，我们可以说我们的模型表现比盲目基准性能模型更好。

# 另请参阅

要了解 PySpark 数据框中`describe()`方法的更多信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/api/python/pyspark.sql.html#pyspark.sql.DataFrame.describe`](http://spark.apache.org/docs/2.2.0/api/python/pyspark.sql.html#pyspark.sql.DataFrame.describe)
