# 精通 Spark 数据科学（三）

> 原文：[`zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25`](https://zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：构建推荐系统

如果要选择一个算法来向公众展示数据科学，推荐系统肯定会成为其中的一部分。今天，推荐系统无处不在。它们之所以如此受欢迎，原因在于它们的多功能性、实用性和广泛适用性。无论是根据用户的购物行为推荐产品，还是根据观看偏好建议新电影，推荐系统现在已经成为生活的一部分。甚至可能是这本书是基于你的社交网络偏好、工作状态或浏览历史等营销公司所知道的信息神奇地推荐给你的。

在本章中，我们将演示如何使用原始音频信号推荐音乐内容。为此，我们将涵盖以下主题：

+   使用 Spark 处理存储在 HDFS 上的音频文件

+   学习关于*傅立叶变换*用于音频信号转换

+   使用 Cassandra 作为在线和离线层之间的缓存层

+   使用*PageRank*作为无监督的推荐算法

+   将 Spark 作业服务器与 Play 框架集成，构建端到端原型

# 不同的方法

推荐系统的最终目标是根据用户的历史使用和偏好建议新的物品。基本思想是对客户过去感兴趣的任何产品使用排名。这种排名可以是显式的（要求用户对电影进行 1 到 5 的排名）或隐式的（用户访问此页面的次数）。无论是购买产品、听歌曲还是阅读文章，数据科学家通常从两个不同的角度解决这个问题：*协同过滤*和*基于内容的过滤*。

## 协同过滤

使用这种方法，我们通过收集有关人们行为的更多信息来利用大数据。尽管个体在定义上是独特的，但他们的购物行为通常不是，总是可以找到一些与其他人的相似之处。推荐的物品将针对特定个人，但它们将通过将用户的行为与类似用户的行为相结合来推导。这是大多数零售网站的著名引用：

> *“购买这个的人也购买了那个……”*

当然，这需要关于客户、他们的过去购买以及其他客户的足够信息进行比较。因此，一个主要的限制因素是物品必须至少被查看一次才能被列为潜在的推荐物品。事实上，直到物品被查看/购买至少一次，我们才能推荐该物品。

### 注意

协同过滤的鸢尾花数据集通常使用 LastFM 数据集的样本进行：[`labrosa.ee.columbia.edu/millionsong/lastfm`](http://labrosa.ee.columbia.edu/millionsong/lastfm)。

## 基于内容的过滤

与使用其他用户相似性不同的替代方法涉及查看产品本身以及客户过去感兴趣的产品类型。如果你对*古典音乐*和*速度金属*都感兴趣，那么可以安全地假设你可能会购买（至少考虑）任何将古典节奏与重金属吉他独奏混合的新专辑。这样的推荐在协同过滤方法中很难找到，因为你周围没有人分享你的音乐口味。

这种方法的主要优势是，假设我们对要推荐的内容有足够的了解（比如类别、标签等），即使没有人看过它，我们也可以推荐一个新的物品。缺点是，模型可能更难建立，并且选择正确的特征而不丢失信息可能具有挑战性。

## 自定义方法

由于本书的重点是*数据科学中的 Spark*，我们希望为读者提供一种新颖的创新方式来解决推荐问题，而不仅仅是解释任何人都可以使用现成的 Spark API 构建的标准协同过滤算法，并遵循基本教程[`spark.apache.org/docs/latest/mllib-collaborative-filtering.html`](http://spark.apache.org/docs/latest/mllib-collaborative-filtering.html)。让我们从一个假设开始：

*如果我们要向最终用户推荐歌曲，我们是否可以构建一个系统，不是基于人们喜欢或不喜欢的歌曲，也不是基于歌曲属性（流派、艺术家），而是基于歌曲的真实声音和你对它的感觉呢？*

为了演示如何构建这样一个系统（因为您可能没有访问包含音乐内容和排名的公共数据集，至少是合法的），我们将解释如何使用您自己的个人音乐库在本地构建它。随时加入！

# 未知数据

以下技术可以被视为现代大多数数据科学家工作方式的一种改变。虽然处理结构化和非结构化文本很常见，但处理原始二进制数据却不太常见，原因在于计算机科学和数据科学之间的差距。文本处理局限于大多数人熟悉的一套标准操作，即获取、解析和存储等。我们将直接处理音频，将未知信号数据转换和丰富为知情的转录。通过这样做，我们实现了一种类似于教计算机从音频文件中“听到”声音的新型数据管道。

我们在这里鼓励的第二个（突破性）想法是，改变数据科学家如今与 Hadoop 和大数据打交道的方式。虽然许多人仍然认为这些技术只是*又一个数据库*，但我们想展示使用这些工具可以获得的广泛可能性。毕竟，没有人会嘲笑能够训练机器与客户交谈或理解呼叫中心录音的数据科学家。

## 处理字节

首先要考虑的是音频文件格式。`.wav`文件可以使用`AudioSystem`库（来自`javax.sound`）进行处理，而`.mp3`则需要使用外部编解码库进行预处理。如果我们从`InputStream`中读取文件，我们可以创建一个包含音频信号的输出字节数组，如下所示：

```scala
def readFile(song: String) = {
  val is = new FileInputStream(song)
   processSong(is)
}
def processSong(stream: InputStream): Array[Byte] = {

   val bufferedIn = new BufferedInputStream(stream)
   val out = new ByteArrayOutputStream
   val audioInputStream = AudioSystem.getAudioInputStream(bufferedIn)

   val format = audioInputStream.getFormat
   val sizeTmp = Math.rint((format.getFrameRate *
                  format.getFrameSize) /
                  format.getFrameRate)
                .toInt

  val size = (sizeTmp + format.getFrameSize) -
             (sizeTmp % format.getFrameSize)

   val buffer = new ArrayByte

   var available = true
   var totalRead = 0
   while (available) {
     val c = audioInputStream.read(buffer, 0, size)
     totalRead += c
     if (c > -1) {
       out.write(buffer, 0, c)
     } else {
       available = false
     }
   }

   audioInputStream.close()
   out.close()
   out.toByteArray
 }
```

歌曲通常使用 44KHz 的采样率进行编码，根据**奈奎斯特**定理，这是人耳可以感知的最高频率的两倍（覆盖范围从 20Hz 到 20KHz）。

### 注意

有关奈奎斯特定理的更多信息，请访问：[`redwood.berkeley.edu/bruno/npb261/aliasing.pdf`](http://redwood.berkeley.edu/bruno/npb261/aliasing.pdf)。

为了表示人类可以听到的声音，我们需要每秒大约 44,000 个样本，因此立体声（两个声道）每秒需要 176,400 字节。后者是以下字节频率：

```scala
val format = audioInputStream.getFormat

val sampleRate = format.getSampleRate

val sizeTmp = Math.rint((format.getFrameRate *
                format.getFrameSize) /
                format.getFrameRate)
              .toInt

 val size = (sizeTmp + format.getFrameSize) -
           (sizeTmp % format.getFrameSize)

 val byteFreq = format.getFrameSize * format.getFrameRate.toInt
```

最后，我们通过处理输出的字节数组并绘制样本数据的前几个字节（在本例中，*图 1*显示了马里奥兄弟主题曲）来访问音频信号。请注意，可以使用字节索引和字节频率值检索时间戳，如下所示：

```scala
val data: Array[Byte] = processSong(inputStream)

val timeDomain: Array[(Double, Int)] = data
  .zipWithIndex
  .map { case (b, idx) =>
      (minTime + idx * 1000L / byteFreq.toDouble, b.toInt)
   }
```

![处理字节](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_001.jpg)

图 1：马里奥兄弟主题曲 - 时域

为了方便起见，我们将所有这些音频特征封装到一个`Audio`案例类中（如下面的代码段所示），随着我们在本章中的进展，我们将添加额外的实用方法：

```scala
case class Audio(data: Array[Byte],
                byteFreq: Int,
                sampleRate: Float,
                minTime: Long,
                id: Int= 0) {

  def duration: Double =
    (data.length + 1) * 1000L / byteFreq.toDouble

  def timeDomain: Array[(Double, Int)] = data
   .zipWithIndex
   .map { case (b, idx) =>
        (minTime + idx * 1000L / byteFreq.toDouble, b.toInt)
    }

  def findPeak: Float = {
    val freqDomain = frequencyDomain()
    freqDomain
     .sortBy(_._2)
     .reverse
     .map(_._1)
     .head
  }

 // Next to come

 }
```

## 创建可扩展的代码

现在我们已经创建了从`.wav`文件中提取音频信号的函数（通过`FileInputStream`），自然的下一步是使用它来处理存储在 HDFS 上的其余记录。正如在前几章中已经强调的那样，一旦逻辑在单个记录上运行，这并不是一个困难的任务。事实上，Spark 自带了一个处理二进制数据的实用程序，因此我们只需插入以下函数：

```scala
def read(library: String, sc: SparkContext) = {
   sc.binaryFiles(library)
     .filter { case (filename, stream) =>
       filename.endsWith(".wav")
     }
     .map { case (filename, stream) =>
       val audio =  processSong(stream.open())
       (filename, audio)
     }
}

val audioRDD: RDD[(String, Audio)] = read(library, sc)
```

我们确保只将`.wav`文件发送到我们的处理器，并获得一个由文件名（歌曲名）和其对应的`Audio` case 类（包括提取的音频信号）组成的新 RDD。

### 提示

Spark 的`binaryFiles`方法读取整个文件（不进行分割）并输出一个包含文件路径和其对应输入流的 RDD。因此，建议处理相对较小的文件（可能只有几兆字节），因为这显然会影响内存消耗和性能。

## 从时间到频率域

访问音频时域是一个很大的成就，但遗憾的是它本身并没有太多价值。然而，我们可以使用它来更好地理解信号的真实含义，即提取它包含的隐藏频率。当然，我们可以使用*傅里叶变换*将时域信号转换为频域。

### 注意

您可以在[`www.phys.hawaii.edu/~jgl/p274/fourier_intro_Shatkay.pdf`](http://www.phys.hawaii.edu/~jgl/p274/fourier_intro_Shatkay.pdf)了解更多关于*傅里叶变换*的知识。

总之，不需要过多细节或复杂的方程，约瑟夫·傅里叶在他的传奇和同名公式中所做的基本假设是，所有信号都由不同频率和相位的正弦波的无限累积组成。

### 快速傅里叶变换

**离散傅里叶变换**（**DFT**）是不同正弦波的总和，并可以使用以下方程表示：

![快速傅里叶变换](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_002.jpg)

尽管使用蛮力方法实现这个算法是微不足道的，但它的效率非常低*O(n²)*，因为对于每个数据点*n*，我们必须计算*n*个指数的和。因此，一首三分钟的歌曲将产生*(3 x 60 x 176,400)²≈ 10¹⁵*数量的操作。相反，Cooley 和 Tukey 采用了一种将 DFT 的时间复杂度降低到*O(n.log(n))*的分治方法，贡献了**快速傅里叶变换**（**FFT**）。

### 注意

描述 Cooley 和 Tukey 算法的官方论文可以在网上找到：[`www.ams.org/journals/mcom/1965-19-090/S0025-5718-1965-0178586-1/S0025-5718-1965-0178586-1.pdf`](http://www.ams.org/journals/mcom/1965-19-090/S0025-5718-1965-0178586-1/S0025-5718-1965-0178586-1.pdf)

幸运的是，现有的 FFT 实现是可用的，因此我们将使用`org.apache.commons.math3`提供的基于 Java 的库来计算 FFT。使用这个库时，我们只需要确保我们的输入数据用零填充，使得总长度是 2 的幂，并且可以分成奇偶序列：

```scala
def fft(): Array[Complex] = {

  val array = Audio.paddingToPowerOf2(data)
  val transformer = new FastFourierTransformer(
                         DftNormalization.STANDARD)

  transformer.transform(array.map(_.toDouble),
      TransformType.FORWARD)

}
```

这将返回一个由实部和虚部组成的`Complex`数字数组，并可以轻松转换为频率和幅度（或幅度）如下。根据奈奎斯特定理，我们只需要一半的频率：

```scala
def frequencyDomain(): Array[(Float, Double)] = {

   val t = fft()
   t.take(t.length / 2) // Nyquist
   .zipWithIndex
   .map { case (c, idx) =>
      val freq = (idx + 1) * sampleRate / t.length
      val amplitude =  sqrt(pow(c.getReal, 2) +
                         pow(c.getImaginary, 2))
      val db = 20 * log10(amplitude)
      (freq, db)
    }

 }
```

最后，我们将这些函数包含在`Audio` case 类中，并绘制马里奥兄弟主题曲前几秒的频域：

![快速傅里叶变换](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_003.jpg)

图 2：马里奥兄弟主题曲-频域

在图 2 中，可以看到在中高频范围（4KHz 至 7KHz 之间）有显著的峰值，我们将使用这些作为歌曲的指纹。

### 按时间窗口采样

尽管更有效，但 FFT 仍然是一个昂贵的操作，因为它的高内存消耗（记住，一首典型的三分钟歌曲将有大约*3 x 60 x 176,400*个点要处理）。当应用于大量数据点时，这变得特别棘手，因此必须考虑大规模处理。

我们不是查看整个频谱，而是使用时间窗口对我们的歌曲进行采样。事实上，完整的 FFT 无论如何都没有用，因为我们想知道每个主要频率被听到的时间。因此，我们将`Audio`类迭代地分割成 20 毫秒样本的较小的案例类。这个时间框应该足够小，以便进行分析，这意味着 FFT 可以被计算，并且足够密集，以确保提取足够的频率，以提供足够的音频指纹。20 毫秒的产生的块将大大增加我们 RDD 的总体大小：

```scala
def sampleByTime(duration: Double = 20.0d,
                padding: Boolean = true): List[Audio] = {

   val  size = (duration * byteFreq / 1000.0f).toInt
   sample(size, padding)

 }

 def sample(size: Int= math.pow(2, 20).toInt,
          padding: Boolean = true): List[Audio] = {

   Audio
    .sample(data, size, padding)
    .zipWithIndex
    .map { case (sampleAudio, idx) =>
      val firstByte = idx * size
       val firstTime = firstByte * 1000L / byteFreq.toLong
       Audio(
           sampleAudio,
           byteFreq,
           sampleRate,
           firstTime,
           idx
      )
    }

 }

val sampleRDD = audioRDDflatMap { case (song, audio) =>
   audio.sampleByTime()
    .map { sample =>
       (song, sample)
     }
 }
```

### 提示

虽然这不是我们的主要关注点，但可以通过重新组合内部和外部 FFT 的样本，并应用一个扭曲因子[`en.wikipedia.org/wiki/Twiddle_factor`](https://en.wikipedia.org/wiki/Twiddle_factor)来重建整个信号的完整 FFT 频谱。当处理具有有限可用内存的大型记录时，这可能是有用的。

### 提取音频签名

现在我们有多个样本在规则的时间间隔内，我们可以使用 FFT 提取频率签名。为了生成一个样本签名，我们尝试在不同的频段中找到最接近的音符，而不是使用精确的峰值（可能是近似的）。这提供了一个近似值，但这样做可以克服原始信号中存在的任何噪音问题，因为噪音会干扰我们的签名。

我们查看以下频段 20-60 Hz，60-250Hz，250-2000Hz，2-4Kz 和 4-6Kz，并根据以下频率参考表找到最接近的音符。这些频段不是随机的。它们对应于不同乐器的不同范围（例如，低音提琴的频段在 50 到 200Hz 之间，短笛在 500 到 5KHz 之间）。

![提取音频签名](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_08_04.jpg)

图 3：频率音符参考表

*图 4*显示了我们马里奥兄弟主题曲在较低频段的第一个样本。我们可以看到 43Hz 的最大幅度对应于音符**F**的主音：

![提取音频签名](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_005.jpg)

图 4：马里奥兄弟主题曲-低频

对于每个样本，我们构建一个由五个字母组成的哈希（比如[**E**-**D#**-**A**-**B**-**B**-**F**]），对应于前面频段中最强的音符（最高峰）。我们认为这个哈希是该特定 20 毫秒时间窗口的指纹。然后我们构建一个由哈希值组成的新 RDD（我们在`Audio`类中包括一个哈希函数）：

```scala
def hash: String = {
  val freqDomain = frequencyDomain()
  freqDomain.groupBy { case (fq, db) =>
    Audio.getFrequencyBand(fq)
  }.map { case (bucket, frequencies) =>
    val (dominant, _) = frequencies.map { case (fq, db) =>
      (Audio.findClosestNote(fq), db)
    }.sortBy { case (note, db) =>
      db
    }.last
    (bucket, dominant)
  }.toList
 .sortBy(_._1)
 .map(_._2)
 .mkString("-")
 }

*/** 
*001 Amadeus Mozart - Requiem (K. 626)        E-D#-A-B-B-F* 
*001 Amadeus Mozart - Requiem (K. 626)        G#-D-F#-B-B-F* 
*001 Amadeus Mozart - Requiem (K. 626)        F#-F#-C-B-C-F* 
*001 Amadeus Mozart - Requiem (K. 626)        E-F-F#-B-B-F* 
*001 Amadeus Mozart - Requiem (K. 626)        E-F#-C#-B-B-F* 
*001 Amadeus Mozart - Requiem (K. 626)        B-E-F-A#-C#-F* 
**/*

```

现在我们将所有共享相同哈希的歌曲 ID 分组，以构建一个唯一哈希的 RDD：

```scala
case class HashSongsPair(
                         id: String,
                         songs: List[Long]
                         )

 val hashRDD = sampleRDD.map { case (id, sample) =>
   (sample.hash, id)
  }
 .groupByKey()
 .map { case (id, songs) =>
    HashSongsPair(id, songs.toList)
  }
```

我们的假设是，当一个哈希在特定的时间窗口内在一首歌中被定义时，类似的歌曲可能共享相似的哈希，但两首歌拥有完全相同的哈希（并且顺序相同）将是真正相同的；一个可能分享我的部分 DNA，但一个拥有完全相同的 DNA 将是我的完美克隆。

如果一个音乐爱好者在听柴可夫斯基的 D 大调协奏曲时感到幸运，我们能否推荐帕赫贝尔的 D 大调卡农，仅仅是因为它们都有一个音乐节奏（即，D 音周围的共同频率）？

仅基于某些频段来推荐播放列表是否有效（和可行）？当然，仅仅频率本身是不足以完全描述一首歌的。节奏、音色或韵律呢？这个模型是否足够完整地准确表示音乐多样性和范围的所有细微差别？可能不是，但出于数据科学的目的，还是值得调查的！

# 构建歌曲分析器

然而，在深入研究推荐系统之前，读者可能已经注意到我们能够从信号数据中提取出一个重要的属性。由于我们在规则的时间间隔内生成音频签名，我们可以比较签名并找到潜在的重复项。例如，给定一首随机歌曲，我们应该能够根据先前索引的签名猜出标题。事实上，这是许多公司在提供音乐识别服务时采取的确切方法。更进一步，我们可能还可以提供关于乐队音乐影响的见解，甚至进一步，也许甚至可以识别歌曲剽窃，最终解决 Led Zeppelin 和美国摇滚乐队 Spirit 之间的*Stairway to Heaven*争议[`consequenceofsound.net/2014/05/did-led-zeppelin-steal-stairway-to-heaven-legendary-rock-band-facing-lawsuit-from-former-tourmates/`](http://consequenceofsound.net/2014/05/did-led-zeppelin-steal-stairway-to-heaven-legendary-rock-band-facing-lawsuit-from-former-tourmates/)。

考虑到这一点，我们将从我们的推荐用例中分离出来，继续深入研究歌曲识别。接下来，我们将构建一个分析系统，能够匿名接收一首歌曲，分析其流，并返回歌曲的标题（在我们的情况下，是原始文件名）。

## 销售数据科学就像销售杯子蛋糕

可悲的是，数据科学旅程中经常被忽视的一个方面是数据可视化。换句话说，如何将结果呈现给最终用户。虽然许多数据科学家乐意在 Excel 电子表格中呈现他们的发现，但今天的最终用户渴望更丰富、更沉浸式的体验。他们经常希望与数据进行*交互*。事实上，为最终用户提供一个完整的、端到端的用户体验，即使是一个简单的用户体验，也是激发对你的科学兴趣的好方法；将一个简单的概念证明变成一个人们可以轻松理解的原型。由于 Web 2.0 技术的普及，用户的期望很高，但幸运的是，有各种免费的开源产品可以帮助，例如 Mike Bostock 的 D3.js，这是一个流行的框架，提供了一个工具包，用于创建这样的用户界面。

没有丰富的数据可视化的数据科学就像试图销售没有糖衣的蛋糕，很少有人会信任成品。因此，我们将为我们的分析系统构建一个用户界面。但首先，让我们从 Spark 中获取音频数据（我们的哈希目前存储在 RDD 内存中），并将其存储到一个面向 Web 的数据存储中。

### 使用 Cassandra

我们需要一个快速、高效和分布式的键值存储来保存所有我们的哈希值。尽管许多数据库都适用于此目的，但我们将选择 Cassandra 来演示其与 Spark 的集成。首先，使用 Maven 依赖项导入 Cassandra 输入和输出格式：

```scala
<dependency>
  <groupId>com.datastax.spark</groupId>
  <artifactId>spark-cassandra-connector_2.11</artifactId>            
  <version>2.0.0</version>
</dependency> 

```

正如你所期望的那样，将 RDD 从 Spark 持久化（和检索）到 Cassandra 相对来说是相当简单的：

```scala
import com.datastax.spark.connector._

 val keyspace = "gzet"
 val table = "hashes"

 // Persist RDD
 hashRDD.saveAsCassandraTable(keyspace, table)

 // Retrieve RDD
 val retrievedRDD = sc.cassandraTableHashSongsPair
```

这将在 keyspace `gzet`上创建一个新的`hashes`表，从`HashSongsPair`对象中推断出模式。以下是执行的等效 SQL 语句（仅供参考）：

```scala
CREATE TABLE gzet.hashes (
  id text PRIMARY KEY,
  songs list<bigint>
)
```

### 使用 Play 框架

由于我们的 Web UI 将面对将歌曲转换为频率哈希所需的复杂处理，我们希望它是一个交互式的 Web 应用程序，而不是一组简单的静态 HTML 页面。此外，这必须以与我们使用 Spark 相同的方式和相同的功能完成（也就是说，相同的歌曲应该生成相同的哈希）。Play 框架（[`www.playframework.com/`](https://www.playframework.com/)）将允许我们这样做，Twitter 的 bootstrap（[`getbootstrap.com/`](http://getbootstrap.com/)）将用于为更专业的外观和感觉添加润色。

尽管这本书不是关于构建用户界面的，但我们将介绍与 Play 框架相关的一些概念，因为如果使用得当，它可以为数据科学家提供巨大的价值。与往常一样，完整的代码可以在我们的 GitHub 存储库中找到。

首先，我们创建一个**数据访问层**，负责处理与 Cassandra 的连接和查询。对于任何给定的哈希，我们返回匹配歌曲 ID 的列表。同样，对于任何给定的 ID，我们返回歌曲名称：

```scala
val cluster = Cluster
  .builder()
  .addContactPoint(cassandraHost)
  .withPort(cassandraPort)
  .build()
val session = cluster.connect()

 def findSongsByHash(hash: String): List[Long] = {
   val stmt = s"SELECT songs FROM hashes WHERE id = '$hash';"
   val results = session.execute(stmt)
   results flatMap { row =>
     row.getList("songs", classOf[Long])
   }
   .toList
 }
```

接下来，我们创建一个简单的**视图**，由三个对象组成，一个`text`字段，一个文件`Upload`和一个`submit`按钮。这几行足以提供我们的用户界面：

```scala
<div>
   <input type="text" class="form-control">
   <span class="input-group-btn">
     <button class="btn-primary">Upload</button>
     <button class="btn-success">Analyze</button>
   </span>
</div>
```

然后，我们创建一个**控制器**，通过`index`和`submit`方法处理`GET`和`POST` HTTP 请求。后者将通过将`FileInputStream`转换为`Audio` case 类，将其分割成 20 毫秒的块，提取 FFT 签名（哈希）并查询 Cassandra 以获取匹配的 ID 来处理上传的文件：

```scala
def index = Action { implicit request =>
   Ok(views.html.analyze("Select a wav file to analyze"))
 }

 def submit = Action(parse.multipartFormData) { request =>
   request.body.file("song").map { upload =>
     val file = new File(s"/tmp/${UUID.randomUUID()}")
     upload.ref.moveTo(file)
     val song = process(file)
     if(song.isEmpty) {
       Redirect(routes.Analyze.index())
         .flashing("warning" -> s"No match")
     } else {
       Redirect(routes.Analyze.index())
         .flashing("success" -> song.get)
     }
   }.getOrElse {
     Redirect(routes.Analyze.index())
       .flashing("error" -> "Missing file")
   }
 }

 def process(file: File): Option[String] = {
   val is = new FileInputStream(file)
   val audio = Audio.processSong(is)
   val potentialMatches = audio.sampleByTime().map {a =>
     queryCassandra(a.hash)
   }
   bestMatch(potentialMatches)
 }
```

最后，我们通过闪烁消息返回匹配结果（如果有的话），并通过为我们的`Analyze`服务定义新的路由将视图和控制器链接在一起：

```scala
GET      /analyze      controllers.Analyze.index
POST     /analyze      controllers.Analyze.submit
```

生成的 UI 如*图 5*所示，并且与我们自己的音乐库完美配合：

![使用 Play 框架](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_006.jpg)

图 5：声音分析器 UI

下图*图 6*显示了端到端的过程：

![使用 Play 框架](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_007.jpg)

图 6：声音分析器过程

如前所述，Play 框架与我们的离线 Spark 作业共享一些代码。这是可能的，因为我们是以函数式风格编程，并且已经很好地分离了关注点。虽然 Play 框架在本质上不与 Spark（即 RDD 和 Spark 上下文对象）兼容，因为它们不依赖于 Spark，我们可以使用我们之前创建的任何函数（比如 Audio 类中的函数）。这是函数式编程的许多优势之一；函数本质上是无状态的，并且是六边形架构采用的关键组件之一：[`wiki.c2.com/?HexagonalArchitecture`](http://wiki.c2.com/?HexagonalArchitecture)。隔离的函数始终可以被不同的执行者调用，无论是在 RDD 内部还是在 Play 控制器内部。

# 构建推荐系统

现在我们已经探索了我们的歌曲分析器，让我们回到推荐引擎。如前所述，我们希望基于从音频信号中提取的频率哈希来推荐歌曲。以 Led Zeppelin 和 Spirit 之间的争议为例，我们期望这两首歌相对接近，因为有指控称它们共享旋律。以这种思路作为我们的主要假设，我们可能会向对《天梯》感兴趣的人推荐《Taurus》。

## PageRank 算法

我们不会推荐特定的歌曲，而是推荐播放列表。播放列表将由按相关性排名的所有歌曲列表组成，从最相关到最不相关。让我们从这样一个假设开始，即人们听音乐的方式与他们浏览网页的方式类似，也就是说，从链接到链接，沿着逻辑路径前进，但偶尔改变方向，或者进行跳转，并浏览到完全不同的网站。继续这个类比，当听音乐时，人们可以继续听相似风格的音乐（因此按照他们最期望的路径前进），或者跳到完全不同流派的随机歌曲。事实证明，这正是谷歌使用 PageRank 算法按照网站的受欢迎程度进行排名的方式。

### 注

有关 PageRank 算法的更多细节，请访问：[`ilpubs.stanford.edu:8090/422/1/1999-66.pdf`](http://ilpubs.stanford.edu:8090/422/1/1999-66.pdf)。

网站的受欢迎程度是通过它指向（并被引用）的链接数量来衡量的。在我们的音乐用例中，受欢迎程度是建立在给定歌曲与所有邻居共享的哈希数量上的。我们引入了歌曲共同性的概念，而不是受欢迎程度。

### 构建频率共现图

我们首先从 Cassandra 中读取我们的哈希值，并重新建立每个不同哈希的歌曲 ID 列表。一旦我们有了这个，我们就可以使用简单的`reduceByKey`函数来计算每首歌曲的哈希数量，因为音频库相对较小，我们将其收集并广播到我们的 Spark 执行器：

```scala
val hashSongsRDD = sc.cassandraTableHashSongsPair

 val songHashRDD = hashSongsRDD flatMap { hash =>
     hash.songs map { song =>
       ((hash, song), 1)
     }
   }

 val songTfRDD = songHashRDD map { case ((hash,songId),count) =>
     (songId, count)
   } reduceByKey(_+_)

 val songTf = sc.broadcast(songTfRDD.collectAsMap())
```

接下来，我们通过获取共享相同哈希值的每首歌曲的叉积来构建一个共现矩阵，并计算观察到相同元组的次数。最后，我们将歌曲 ID 和标准化的（使用我们刚刚广播的词频）频率计数包装在 GraphX 的`Edge`类中：

```scala
implicit class CrossableX {
      def crossY = for { x <- xs; y <- ys } yield (x, y)

val crossSongRDD = songHashRDD.keys
    .groupByKey()
    .values
    .flatMap { songIds =>
        songIds cross songIds filter { case (from, to) =>
           from != to
      }.map(_ -> 1)
    }.reduceByKey(_+_)
     .map { case ((from, to), count) =>
       val weight = count.toDouble /
                    songTfB.value.getOrElse(from, 1)
       Edge(from, to, weight)
    }.filter { edge =>
     edge.attr > minSimilarityB.value
   }

val graph = Graph.fromEdges(crossSongRDD, 0L)
```

我们只保留具有大于预定义阈值的权重（意味着哈希共现）的边，以构建我们的哈希频率图。

### 运行 PageRank

与运行 PageRank 时人们通常期望的相反，我们的图是无向的。事实证明，对于我们的推荐系统来说，缺乏方向并不重要，因为我们只是试图找到 Led Zeppelin 和 Spirit 之间的相似之处。引入方向的一种可能方式是查看歌曲的发布日期。为了找到音乐影响，我们可以确实地从最旧的歌曲到最新的歌曲引入一个时间顺序，给我们的边赋予方向性。

在以下的`pageRank`中，我们定义了一个 15%的概率来跳过，或者**跳转**到任意随机歌曲，但这显然可以根据不同的需求进行调整：

```scala
val prGraph = graph.pageRank(0.001, 0.15)
```

最后，我们提取了页面排名的顶点，并将它们保存为 Cassandra 中的播放列表，通过`Song`类的 RDD：

```scala
case class Song(id: Long, name: String, commonality: Double)
val vertices = prGraph
  .vertices
  .mapPartitions { vertices =>
    val songIds = songIdsB
  .value
  .vertices
  .map { case (songId, pr) =>
       val songName = songIds.get(vId).get
        Song(songId, songName, pr)
      }
  }

 vertices.saveAsCassandraTable("gzet", "playlist")
```

读者可能会思考 PageRank 在这里的确切目的，以及它如何作为推荐系统使用？事实上，我们使用 PageRank 的意思是排名最高的歌曲将是与其他歌曲共享许多频率的歌曲。这可能是由于共同的编曲、主题或旋律；或者可能是因为某位特定艺术家对音乐趋势产生了重大影响。然而，这些歌曲应该在理论上更受欢迎（因为它们出现的频率更高），这意味着它们更有可能受到大众的喜爱。

另一方面，低排名的歌曲是我们没有发现与我们所知的任何东西相似的歌曲。要么这些歌曲是如此前卫，以至于没有人在这些音乐理念上进行探索，要么是如此糟糕，以至于没有人想要复制它们！也许它们甚至是由你在叛逆的少年时期听过的那位新兴艺术家创作的。无论哪种情况，随机用户喜欢这些歌曲的机会被视为微不足道。令人惊讶的是，无论是纯粹的巧合还是这种假设真的有意义，这个特定音频库中排名最低的歌曲是 Daft Punk 的--*Motherboard*，这是一个相当原创的标题（尽管很棒），并且有着独特的声音。

## 构建个性化播放列表

我们刚刚看到，简单的 PageRank 可以帮助我们创建一个通用的播放列表。尽管这并不针对任何个人，但它可以作为一个随机用户的播放列表。这是我们在没有任何关于用户偏好的信息时能做出的最好的推荐。我们对用户了解得越多，我们就能越好地个性化播放列表以符合他们真正的喜好。为了做到这一点，我们可能会采用基于内容的推荐方法。

在没有关于用户偏好的预先信息的情况下，我们可以在用户播放歌曲时寻求收集我们自己的信息，并在运行时个性化他们的播放列表。为此，我们将假设我们的用户喜欢他们之前听过的歌曲。我们还需要禁用跳转，并生成一个从特定歌曲 ID 开始的新播放列表。

PageRank 和个性化 PageRank 在计算分数的方式上是相同的（使用传入/传出边的权重），但个性化版本只允许用户跳转到提供的 ID。通过对代码进行简单修改，我们可以使用某个社区 ID（参见第七章，*构建社区*，以获取社区的定义）或使用某种音乐属性，如艺术家或流派，来个性化 PageRank。根据我们之前的图，个性化的 PageRank 实现如下：

```scala
val graph = Graph.fromEdges(edgeRDD, 0L)
val prGraph = graph.personalizedPageRank(id, 0.001, 0.1)
```

在这里，随机跳转到一首歌的机会为零。仍然有 10%的跳过机会，但只在提供的歌曲 ID 的非常小的容差范围内。换句话说，无论我们当前正在听的歌曲是什么，我们基本上定义了 10%的机会播放我们提供的歌曲作为种子。

## 扩展我们的杯子蛋糕工厂

与我们的歌曲分析器原型类似，我们希望以一个漂亮整洁的用户界面向我们的想象客户呈现我们建议的播放列表。

### 构建播放列表服务

仍然使用 Play 框架，我们的技术栈保持不变，这次我们只是创建了一个新的端点（一个新的路由）：

```scala
GET       /playlist      controllers.Playlist.index
```

就像以前一样，我们创建了一个额外的控制器来处理简单的 GET 请求（当用户加载播放列表网页时触发）。我们加载存储在 Cassandra 中的通用播放列表，将所有这些歌曲包装在`Playlist` case 类中，并将其发送回`playlist.scala.html`视图。控制器模型如下：

```scala
def getSongs: List[Song] = {
   val s = "SELECT id, name, commonality FROM gzet.playlist;"
   val results = session.execute(s)
   results map { row =>
     val id = row.getLong("id")
     val name = row.getString("name")
     val popularity = row.getDouble("commonality")
     Song(id, name, popularity)
   } toList
 }

 def index = Action { implicit request =>
   val playlist = models.Playlist(getSongs)
   Ok(views.html.playlist(playlist))
 }
```

视图保持相当简单，因为我们遍历所有歌曲以按常见程度（从最常见到最不常见）排序进行显示：

```scala
@(playlist: Playlist)

@displaySongs(playlist: Playlist) = {
   @for(node <- playlist.songs.sortBy(_.commonality).reverse) {
     <a href="/playlist/@node.id" class="list-group-item">
       <iclass="glyphiconglyphicon-play"></i>
       <span class="badge">
         @node.commonality
       </span>
       @node.name
     </a>
   }
 }

 @main("playlist") {
   <div class="row">
     <div class="list-group">
       @displaySongs(playlist)
     </div>
   </div>
 }
```

### 注意

注意每个列表项中的`href`属性 - 每当用户点击列表中的歌曲时，我们将生成一个新的`REST`调用到/playlist/id 端点（这在下一节中描述）。

最后，我们很高兴地揭示了*图 7*中推荐的（通用）播放列表。由于我们不知道的某种原因，显然一个对古典音乐一窍不通的新手应该开始听*古斯塔夫·马勒，第五交响曲*。

![构建播放列表服务](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_08_08-2.jpg)

图 7：播放列表推荐器

### 利用 Spark 作业服务器

又来了一个有趣的挑战。尽管我们的通用播放列表和 PageRank 分数的歌曲列表存储在 Cassandra 中，但对于个性化播放列表来说，这是不可行的，因为这将需要对所有可能的歌曲 ID 的所有 PageRank 分数进行预计算。由于我们希望在伪实时中构建个性化播放列表，并且可能会定期加载新歌曲，所以我们需要找到一个比在每个请求上启动`SparkContext`更好的方法。

第一个限制是 PageRank 函数本质上是一个分布式过程，不能在 Spark 的上下文之外使用（也就是说，在我们的 Play 框架的 JVM 内部）。我们知道在每个 http 请求上创建一个新的 Spark 作业肯定会有点过度，所以我们希望启动一个单独的 Spark 作业，并且只在需要时处理新的图，最好是通过一个简单的 REST API 调用。

第二个挑战是我们不希望重复从 Cassandra 中加载相同的图数据集。这应该加载一次并缓存在 Spark 内存中，并在不同的作业之间共享。在 Spark 术语中，这将需要从共享上下文中访问 RDD。

幸运的是，Spark 作业服务器解决了这两个问题（[`github.com/spark-jobserver/spark-jobserver`](https://github.com/spark-jobserver/spark-jobserver)）。尽管这个项目还相当不成熟（或者至少还不够成熟），但它是展示数据科学的完全可行的解决方案。

为了本书的目的，我们只使用本地配置编译和部署 Spark 作业服务器。我们强烈建议读者深入了解作业服务器网站（参见上面的链接），以获取有关打包和部署的更多信息。一旦我们的服务器启动，我们需要创建一个新的上下文（意味着启动一个新的 Spark 作业），并为处理与 Cassandra 的连接的附加配置设置。我们给这个上下文一个名称，以便以后可以使用它：

```scala
curl -XPOST 'localhost:8090/contexts/gzet?\
  num-cpu-cores=4&\
  memory-per-node=4g&\
  spark.executor.instances=2&\
  spark.driver.memory=2g&\
  passthrough.spark.cassandra.connection.host=127.0.0.1&\
  passthrough.spark.cassandra.connection.port=9042'
```

下一步是修改我们的代码以符合 Spark 作业服务器的要求。我们需要以下依赖项：

```scala
<dependency>
   <groupId>spark.jobserver</groupId>
   <artifactId>job-server-api_2.11</artifactId>
   <version>spark-2.0-preview</version>
 </dependency>
```

我们修改我们的 SparkJob，使用作业服务器提供的`SparkJob`接口的签名。这是作业服务器所有 Spark 作业的要求：

```scala
object PlaylistBuilder extends SparkJob {

  override def runJob(
    sc: SparkContext,
    jobConfig: Config
  ): Any = ???

  override def validate(
    sc: SparkContext,
    config: Config
  ): SparkJobValidation = ???

}
```

在`validate`方法中，我们确保所有作业要求将得到满足（例如该作业所需的输入配置），在`runJob`中，我们执行我们的正常 Spark 逻辑，就像以前一样。最后的变化是，虽然我们仍然将我们的通用播放列表存储到 Cassandra 中，但我们将在 Spark 共享内存中缓存节点和边缘 RDD，以便将其提供给进一步的作业。这可以通过扩展`NamedRddSupport`特性来实现。

我们只需保存边缘和节点 RDD（请注意，目前不支持保存`Graph`对象）以便在后续作业中访问图：

```scala
this.namedRdds.update("rdd:edges", edgeRDD)
this.namedRdds.update("rdd:nodes", nodeRDD)
```

从个性化的`Playlist`作业中，我们按以下方式检索和处理我们的 RDD：

```scala
val edgeRDD = this.namedRdds.getEdge.get
val nodeRDD = this.namedRdds.getNode.get

val graph = Graph.fromEdges(edgeRDD, 0L)
```

然后，我们执行我们的个性化 PageRank，但是不会将结果保存回 Cassandra，而是简单地收集前 50 首歌曲。当部署时，由于作业服务器的魔力，此操作将隐式地将此列表输出回客户端：

```scala
val prGraph = graph.personalizedPageRank(id, 0.001, 0.1)

prGraph
 .vertices
 .map { case(vId, pr) =>
   List(vId, songIds.value.get(vId).get, pr).mkString(",")
  }
 .take(50)
```

我们编译我们的代码，并通过给它一个应用程序名称将我们的阴影 jar 文件发布到作业服务器，如下所示：

```scala
curl --data-binary @recommender-core-1.0.jar \
 'localhost:8090/jars/gzet'
```

现在我们几乎准备好部署我们的推荐系统了，让我们回顾一下我们将要演示的内容。我们将很快执行两种不同的用户流程：

+   当用户登录到推荐页面时，我们从 Cassandra 中检索最新的通用播放列表。或者，如果需要，我们会启动一个新的异步作业来创建一个新的播放列表。这将在 Spark 上下文中加载所需的 RDD。

+   当用户播放我们推荐的新歌曲时，我们会同步调用 Spark 作业服务器，并基于这首歌曲的 ID 构建下一个播放列表。

通用 PageRank 播放列表的流程如*图 8*所示：

![利用 Spark 作业服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_009.jpg)

图 8：播放列表推荐器流程

个性化 PageRank 播放列表的流程如图 9 所示：

![利用 Spark 作业服务器](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_08_010.jpg)

图 9：个性化播放列表推荐器流程

### 用户界面

最后剩下的问题是从 Play 框架的服务层调用 Spark 作业服务器。尽管这是通过`java.net`包以编程方式完成的，但由于它是一个 REST API，等效的`curl`请求在以下代码片段中显示：

```scala
# Asynchronous Playlist Builder
curl -XPOST 'localhost:8090/jobs?\
 context=gzet&\
 appName=gzet&\
 classPath=io.gzet.recommender.PlaylistBuilder'

# Synchronous Personalized Playlist for song 12
curl -XPOST -d "song.id=12" 'localhost:8090/jobs?\
 context=gzet&\
 appName=gzet&\
 sync=true&\
 timeout=60000&\
 classPath=io.gzet.recommender.PersonalizedPlaylistBuilder'
```

最初，当我们构建 HTML 代码时，我们引入了一个指向`/playlist/${id}`的链接或`href`。这个 REST 调用将被转换为对`Playlist`控制器的 GET 请求，并绑定到您的`personalize`函数，如下所示：

```scala
GET /playlist/:id controllers.Playlist.personalize(id: Long) 

```

对 Spark 作业服务器的第一次调用将同步启动一个新的 Spark 作业，从作业输出中读取结果，并重定向到相同的页面视图，这次是基于这首歌曲的 ID 更新的播放列表：

```scala
def personalize(id: Long) = Action { implicit request =>
   val name = cassandra.getSongName(id)
   try {
     val nodes = sparkServer.generatePlaylist(id)
     val playlist = models.Playlist(nodes, name)
     Ok(views.html.playlist(playlist))
   } catch {
     case e: Exception =>
       Redirect(routes.Playlist.index())
         .flashing("error" -> e.getMessage)
   }
 }
```

结果 UI 显示在*图 10*中。每当用户播放一首歌，播放列表都将被更新和显示，充当一个完整的排名推荐引擎。

![用户界面](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_08_11-1.jpg)

图 10：个性化播放列表推荐流程

# 总结

尽管我们的推荐系统可能并没有采用典型的教科书方法，也可能不是最准确的推荐系统，但它确实代表了数据科学中最常见技术之一的一个完全可演示且非常有趣的方法。此外，通过持久数据存储、REST API 接口、分布式共享内存缓存和基于现代 Web 2.0 的用户界面，它提供了一个相当完整和全面的候选解决方案。

当然，要将这个原型产品打造成一个生产级产品仍需要大量的努力和专业知识。在信号处理领域仍有改进空间。例如，可以通过使用响度滤波器来改善声压，并减少信号噪音，[`languagelog.ldc.upenn.edu/myl/StevensJASA1955.pdf`](http://languagelog.ldc.upenn.edu/myl/StevensJASA1955.pdf)，通过提取音高和旋律，或者更重要的是，通过将立体声转换为单声道信号。

### 注

所有这些过程实际上都是研究的一个活跃领域 - 读者可以查看以下一些出版物：[`www.justinsalamon.com/publications.html`](http://www.justinsalamon.com/publications.html) 和 [`www.mattmcvicar.com/publications/`](http://www.mattmcvicar.com/publications/)。

此外，我们质疑如何通过使用简单（交互式）用户界面来改进数据科学演示。正如提到的，这是一个经常被忽视的方面，也是演示的一个关键特点。即使在项目的早期阶段，投资一些时间进行数据可视化也是值得的，因为当说服商业人士你的产品的可行性时，它可能特别有用。

最后，作为一个有抱负的章节，我们探索了在 Spark 环境中解决数据科学用例的创新方法。通过平衡数学和计算机科学的技能，数据科学家应该可以自由探索，创造，推动可行性的边界，承担人们认为不可能的任务，但最重要的是，享受数据带来的乐趣。因为这正是为什么成为数据科学家被认为是 21 世纪最性感的工作的主要原因。

这一章是一个音乐插曲。在下一章中，我们将通过使用 Twitter 数据来引导 GDELT 文章的分类模型来分类 GDELT 文章，这无疑是另一个雄心勃勃的任务。


# 第九章：新闻词典和实时标记系统

虽然分层数据仓库将数据存储在文件夹中的文件中，但典型的基于 Hadoop 的系统依赖于扁平架构来存储您的数据。如果没有适当的数据治理或对数据的清晰理解，将数据湖变成沼泽的机会是不可否认的，其中一个有趣的数据集，如 GDELT，将不再是一个包含大量非结构化文本文件的文件夹。因此，数据分类可能是大规模组织中最广泛使用的机器学习技术之一，因为它允许用户正确分类和标记其数据，将这些类别作为其元数据解决方案的一部分发布，从而以最有效的方式访问特定信息。如果没有一个在摄入时执行的适当标记机制，理想情况下，找到关于特定主题的所有新闻文章将需要解析整个数据集以寻找特定关键字。在本章中，我们将描述一种创新的方法，以一种非监督的方式和近乎实时地使用 Spark Streaming 和 1%的 Twitter firehose 标记传入的 GDELT 数据。

我们将涵盖以下主题：

+   使用 Stack Exchange 数据引导朴素贝叶斯分类器

+   Lambda 与 Kappa 架构用于实时流应用程序

+   在 Spark Streaming 应用程序中使用 Kafka 和 Twitter4J

+   部署模型时的线程安全性

+   使用 Elasticsearch 作为缓存层

# 机械土耳其人

数据分类是一种监督学习技术。这意味着您只能预测您从训练数据集中学到的标签和类别。因为后者必须被正确标记，这成为我们将在本章中解决的主要挑战。

## 人类智能任务

在新闻文章的背景下，我们的数据没有得到适当的标记；我们无法从中学到任何东西。数据科学家的常识是手动开始标记一些输入记录，这些记录将作为训练数据集。然而，因为类别的数量可能相对较大，至少在我们的情况下（数百个标签），需要标记的数据量可能相当大（数千篇文章），并且需要巨大的努力。一个解决方案是将这项繁琐的任务外包给“机械土耳其人”，这个术语被用来指代历史上最著名的骗局之一，一个*自动*国际象棋选手愚弄了世界上大多数领导人（[`en.wikipedia.org/wiki/The_Turk`](https://en.wikipedia.org/wiki/The_Turk)）。这通常描述了一个可以由机器完成的过程，但实际上是由一个隐藏的人完成的，因此是一个人类智能任务。

对于读者的信息，亚马逊已经启动了一个机械土耳其人计划（[`www.mturk.com/mturk/welcome`](https://www.mturk.com/mturk/welcome)），个人可以注册执行人类智能任务，如标记输入数据或检测文本内容的情感。众包这项任务可能是一个可行的解决方案，假设您可以将这个内部（可能是机密的）数据集分享给第三方。这里描述的另一种解决方案是使用预先存在的标记数据集引导分类模型。

## 引导分类模型

文本分类算法通常从术语频率向量中学习；一种可能的方法是使用具有类似上下文的外部资源训练模型。例如，可以使用从 Stack Overflow 网站的完整转储中学到的类别对未标记的 IT 相关内容进行分类。因为 Stack Exchange 不仅仅是为 IT 专业人士保留的，人们可以在许多不同的上下文中找到各种数据集，这些数据集可以服务于许多目的（[`archive.org/download/stackexchange`](https://archive.org/download/stackexchange)）。

### 从 Stack Exchange 学习

我们将在这里演示如何使用来自 Stack Exchange 网站的与家酿啤酒相关的数据集来引导一个简单的朴素贝叶斯分类模型：

```scala
$ wget https://archive.org/download/stackexchange/beer.stackexchange.com.7z
$ 7z e beer.stackexchange.com.7z
```

我们创建了一些方法，从所有 XML 文档中提取正文和标签，从 HTML 编码的正文中提取干净的文本内容（使用第六章中介绍的 Goose 抓取器，*基于链接的外部数据抓取*），最后将我们的 XML 文档 RDD 转换为 Spark DataFrame。这里没有报告不同的方法，但它们可以在我们的代码库中找到。需要注意的是，Goose 抓取器可以通过提供 HTML 内容（作为字符串）和一个虚拟 URL 来离线使用。

我们提供了一个方便的`parse`方法，可用于预处理来自 Stack Exchange 网站的任何`Post.xml`数据。这个函数是我们的`StackBootstraping`代码的一部分，可以在我们的代码库中找到：

```scala
import io.gzet.tagging.stackoverflow.StackBootstraping

val spark = SparkSession.builder()
  .appName("StackExchange")
  .getOrCreate()

val sc = spark.sparkContext
val rdd = sc.textFile("/path/to/posts.xml")
val brewing = StackBootstraping.parse(rdd)

brewing.show(5)

+--------------------+--------------------+
|                body|                tags|
+--------------------+--------------------+
|I was offered a b...|              [hops]|
|As far as we know...|           [history]|
|How is low/no alc...|           [brewing]|
|In general, what'...|[serving, tempera...|
|Currently I am st...| [pilsener, storage]|
+--------------------+--------------------+
```

### 构建文本特征

有了正确标记的啤酒内容，剩下的过程就是引导算法本身。为此，我们使用一个简单的朴素贝叶斯分类算法，确定给定项目特征的标签的条件概率。我们首先收集所有不同的标签，分配一个唯一的标识符（作为`Double`），并将我们的标签字典广播到 Spark 执行器：

```scala
val labelMap = brewing
  .select("tags")
  .withColumn("tag", explode(brewing("tags")))
  .select("tag")
  .distinct()
  .rdd
  .map(_.getString(0)).zipWithIndex()
  .mapValues(_.toDouble + 1.0d)
labelMap.take(5).foreach(println)

/*
(imperal-stout,1.0)
(malt,2.0)
(lent,3.0)
(production,4.0)
(local,5.0)
*/
```

### 提示

如前所述，请确保在 Spark 转换中使用的大型集合已广播到所有 Spark 执行器。这将减少与网络传输相关的成本。

`LabeledPoint`由标签（作为`Double`）和特征（作为`Vector`）组成。构建文本内容特征的常见做法是构建词项频率向量，其中每个单词在所有文档中对应一个特定的维度。在英语中大约有数十万个维度（英语单词估计数量为 1,025,109），这种高维空间对于大多数机器学习算法来说将特别低效。事实上，当朴素贝叶斯算法计算概率（小于 1）时，由于机器精度问题（如第十四章中描述的数值下溢，*可扩展算法*），存在达到 0 的风险。数据科学家通过使用降维原理来克服这一限制，将稀疏向量投影到更密集的空间中，同时保持距离度量（降维原理将在第十章中介绍，*故事去重和变异*）。尽管我们可以找到许多用于此目的的算法和技术，但我们将使用 Spark 提供的哈希工具。

在* n *（默认为 2²⁰）的向量大小下，其`transform`方法将所有单词分组到* n *个不同的桶中，根据它们的哈希值对桶频率进行求和以构建更密集的向量。

在进行昂贵的降维操作之前，可以通过对文本内容进行词干处理和清理来大大减少向量大小。我们在这里使用 Apache Lucene 分析器：

```scala
<dependency>
   <groupId>org.apache.lucene</groupId>
   <artifactId>lucene-analyzers-common</artifactId>
   <version>4.10.1</version>
 </dependency>
```

我们去除所有标点和数字，并将纯文本对象提供给 Lucene 分析器，将每个干净的单词收集为`CharTermAttribute`：

```scala
def stem(rdd: RDD[(String, Array[String])]) = {

  val replacePunc = """\\W""".r
  val replaceDigitOnly = """\\s\\d+\\s""".r

  rdd mapPartitions { it =>

    val analyzer = new EnglishAnalyzer
    it map { case (body, tags) =>
      val content1 = replacePunc.replaceAllIn(body, " ")
      val content = replaceDigitOnly.replaceAllIn(content1, " ")
      val tReader = new StringReader(content)
      val tStream = analyzer.tokenStream("contents", tReader)
      val term = tStream.addAttribute(classOf[CharTermAttribute])
       tStream.reset()
      val terms = collection.mutable.MutableList[String]()
      while (tStream.incrementToken) {
        val clean = term.toString
        if (!clean.matches(".*\\d.*") && clean.length > 3) {
           terms += clean
        }
      }
      tStream.close()
      (terms.toArray, tags)
     }

  }
```

通过这种方法，我们将文本[Mastering Spark for Data Science - V1]转换为[master spark data science]，从而减少了输入向量中的单词数量（因此减少了维度）。最后，我们使用 MLlib 的`normalizer`类来规范化我们的词项频率向量：

```scala
val hashingTf = new HashingTF()
val normalizer = new Normalizer()

val labeledCorpus = stem(df map { row =>
  val body = row.getString(0)
  val tags = row.getAs[mutable.WrappedArray[String]](1)
  (body, tags)
})

val labeledPoints = labeledCorpus flatMap { case (corpus, tags) =>
  val vector = hashingTf.transform(corpus)
  val normVector = normalizer.transform(vector)
  tags map { tag =>
    val label = bLabelMap.value.getOrElse(tag, 0.0d)
    LabeledPoint(label, normVector)
  }
}
```

### 提示

哈希函数可能会导致由于碰撞而产生严重的高估（两个完全不同含义的单词可能共享相同的哈希值）。我们将在第十章中讨论随机索引技术，以限制碰撞的数量同时保持距离度量。

### 训练朴素贝叶斯模型

我们按照以下方式训练朴素贝叶斯算法，并使用我们没有包含在训练数据点中的测试数据集测试我们的分类器。最后，在下面的例子中显示了前五个预测。左侧的标签是我们测试内容的原始标签；右侧是朴素贝叶斯分类的结果。`ipa`被预测为`hangover`，从而确证了我们分类算法的准确性：

```scala
labeledPoints.cache()
val model: NaiveBayesModel = NaiveBayes.train(labeledPoints)
labeledPoints.unpersist(blocking = false)

model
  .predict(testPoints)
  .map { prediction =>
     bLabelMap.value.map(_.swap).get(prediction).get
   }
  .zip(testLabels)
  .toDF("predicted","original")
  .show(5)

+---------+-----------+
| original|  predicted|
+---------+-----------+
|  brewing|    brewing|
|      ipa|   hangover|
| hangover|   hangover|
| drinking|   drinking|
| pilsener|   pilsener|
+---------+-----------+
```

为了方便起见，我们将所有这些方法抽象出来，并在稍后将使用的`Classifier`对象中公开以下方法：

```scala
def train(rdd: RDD[(String, Array[String])]): ClassifierModel
def predict(rdd: RDD[String]): RDD[String]
```

我们已经演示了如何从外部来源导出标记数据，如何构建词项频率向量，以及如何训练一个简单的朴素贝叶斯分类模型。这里使用的高级工作流程如下图所示，对于大多数分类用例来说都是通用的：

![训练朴素贝叶斯模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_001.jpg)

图 1：分类工作流程

下一步是开始对原始未标记数据进行分类（假设我们的内容仍然与酿酒有关）。这结束了朴素贝叶斯分类的介绍，以及一个自举模型如何从外部资源中获取真实信息。这两种技术将在以下部分中用于我们的分类系统。

## 懒惰，急躁和傲慢

接下来是我们在新闻文章环境中将面临的第二个主要挑战。假设有人花了几天时间手动标记数据，这将解决我们已知类别的分类问题，可能只在回测我们的数据时有效。谁知道明天报纸的新闻标题会是什么；没有人能定义将来将涵盖的所有细粒度标签和主题（尽管仍然可以定义更广泛的类别）。这将需要大量的努力来不断重新评估、重新训练和重新部署我们的模型，每当出现新的热门话题时。具体来说，一年前没有人谈论“脱欧”这个话题；现在这个话题在新闻文章中被大量提及。

根据我们的经验，数据科学家应该记住 Perl 编程语言的发明者 Larry Wall 的一句名言：

> “我们将鼓励您培养程序员的三大美德，懒惰、急躁和傲慢”。

+   *懒惰*会让你付出巨大的努力来减少总体能量消耗

+   *急躁*会让你编写不仅仅是满足你需求的程序，而是能够预测你的需求

+   *傲慢*会让你编写程序，别人不愿意说坏话

我们希望避免与分类模型的准备和维护相关的努力（懒惰），并在程序上预测新主题的出现（急躁），尽管这听起来可能是一个雄心勃勃的任务（但如果不是对实现不可能的过度自豪，那又是什么呢？）。社交网络是一个从中获取真实信息的绝佳地方。事实上，当人们在 Twitter 上发布新闻文章时，他们无意中帮助我们标记我们的数据。我们不需要支付机械土耳其人的费用，当我们潜在地有数百万用户为我们做这项工作时。换句话说，我们将 GDELT 数据的标记外包给 Twitter 用户。

Twitter 上提到的任何文章都将帮助我们构建一个词项频率向量，而相关的标签将被用作正确的标签。在下面的例子中，关于奥巴马总统穿着睡袍会见乔治王子的可爱新闻已被分类为[#Obama]和[#Prince] [`www.wfmynews2.com/entertainment/adorable-prince-george-misses-bedtime-meets-president-obama/149828772`](http://www.wfmynews2.com/entertainment/adorable-prince-george-misses-bedtime-meets-president-obama/149828772)：

![懒惰，急躁和傲慢](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_002.jpg)

图 2：奥巴马总统会见乔治王子，#Obama，#Prince

在以下示例中，我们通过机器学习主题[#DavidBowie]，[#Prince]，[#GeorgeMichael]和[#LeonardCohen]来向 2016 年音乐界的所有巨大损失致敬，这些主题都在同一篇来自《卫报》的新闻文章中（https://www.theguardian.com/music/2016/dec/29/death-stars-musics-greatest-losses-of-2016）：

![懒惰、急躁和傲慢](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_003.jpg)

图 3：2016 年音乐界的巨大损失-来源

使用这种方法，我们的算法将不断自动重新评估，从而自行学习出现的主题，因此以一种非监督的方式工作（尽管在适当意义上是一种监督学习算法）。

# 设计 Spark Streaming 应用程序

构建实时应用程序在架构和涉及的组件方面与批处理处理有所不同。后者可以轻松地自下而上构建，程序员在需要时添加功能和组件，而前者通常需要在一个稳固的架构基础上自上而下构建。事实上，由于数据量和速度（或在流处理上下文中的真实性）的限制，不恰当的架构将阻止程序员添加新功能。人们总是需要清楚地了解数据流如何相互连接，以及它们是如何被处理、缓存和检索的。

## 两种架构的故事

在使用 Apache Spark 进行流处理方面，有两种新兴的架构需要考虑：Lambda 架构和 Kappa 架构。在深入讨论这两种架构的细节之前，让我们讨论它们试图解决的问题，它们有什么共同之处，以及在什么情况下使用每种架构。

### CAP 定理

多年来，处理网络中断一直是高度分布式系统的工程师们关注的问题。以下是一个特别感兴趣的情景，请考虑：

![CAP 定理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_004.jpg)

图 4：分布式系统故障

典型分布式系统的正常运行是用户执行操作，系统使用复制、缓存和索引等技术来确保正确性和及时响应。但当出现问题时会发生什么：

![CAP 定理](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_005.jpg)

图 5：分布式系统的分裂大脑综合症

在这里，网络中断实际上阻止了用户安全地执行他们的操作。是的，一个简单的网络故障引起了一个并不仅仅影响功能和性能的复杂情况，正如你可能期望的那样，还影响了系统的正确性。

事实上，系统现在遭受了所谓的*分裂大脑综合症*。在这种情况下，系统的两个部分不再能够相互通信，因此用户在一侧进行的任何修改在另一侧是不可见的。这几乎就像有两个独立的系统，每个系统都维护着自己的内部状态，随着时间的推移会变得截然不同。至关重要的是，用户在任一侧运行相同查询时可能会报告不同的答案。

这只是分布式系统中失败的一般情况之一，尽管已经花费了大量时间来解决这些问题，但仍然只有三种实际的方法：

1.  在基础问题得到解决之前，阻止用户进行任何更新，并同时保留系统的当前状态（故障前的最后已知状态）作为正确的（即牺牲*分区容忍性*）。

1.  允许用户继续进行更新，但要接受答案可能不同，并且在基础问题得到纠正时必须收敛（即牺牲*一致性*）。

1.  将所有用户转移到系统的一部分，并允许他们继续进行更新。系统的另一部分被视为失败，并接受部分处理能力的降低，直到问题解决为止 - 系统可能因此变得不太响应（即牺牲*可用性*）。

前述的结论更正式地陈述为 CAP 定理（[`nathanmarz.com/blog/how-to-beat-the-cap-theorem.html`](http://nathanmarz.com/blog/how-to-beat-the-cap-theorem.html)）。它认为在一个故障是生活中的事实且你不能牺牲功能性的环境中（1），你必须在一致的答案（2）和完整的功能性（3）之间做出选择。你不能两者兼得，因为这是一种权衡。

### 提示

事实上，更正确的描述是将“故障”描述为更一般的术语“分区容错”，因为这种类型的故障可能指的是系统的任何分割 - 网络中断、服务器重启、磁盘已满等 - 它不一定是特定的网络问题。

不用说，这是一种简化，但尽管如此，在故障发生时，大多数数据处理系统都会属于这些广泛的类别之一。此外，事实证明，大多数传统数据库系统都倾向于一致性，通过使用众所周知的计算机科学方法来实现，如事务、预写日志和悲观锁定。

然而，在今天的在线世界中，用户期望全天候访问服务，其中许多服务都是收入来源；物联网或实时决策，需要一种可扩展的容错方法。因此，人们努力寻求确保在故障发生时可用性的替代方案的努力激增（事实上，互联网本身就是出于这种需求而诞生的）。

事实证明，在实现高可用系统并提供可接受水平一致性之间取得平衡是一种挑战。为了管理必要的权衡，方法往往提供更弱的一致性定义，即*最终一致性*，在这种情况下，通常容忍一段时间的陈旧数据，并且随着时间的推移，正确的数据会得到认可。然而，即使在这种妥协情况下，它们仍然需要使用更复杂的技术，因此更难以构建和维护。

### 提示

在更繁重的实现中，需要使用向量时钟和读修复来处理并发并防止数据损坏。

### 希腊人在这里可以提供帮助

Lambda 和 Kappa 架构都提供了对先前描述的问题更简单的解决方案。它们倡导使用现代大数据技术，如 Apache Spark 和 Apache Kafka 作为一致性可用处理系统的基础，逻辑可以在不需要考虑故障的情况下进行开发。它们适用于具有以下特征的情况：

+   无限的、入站的信息流，可能来自多个来源

+   对非常大的累积数据集进行分析处理

+   用户查询对数据一致性有时间保证

+   对性能下降或停机的零容忍

在具有这些条件的情况下，您可以考虑将任一架构作为一般候选。每种架构都遵循以下核心原则，有助于简化数据一致性、并发访问和防止数据损坏的问题：

+   数据不可变性：数据只能创建或读取。它永远不会被更新或删除。以这种方式处理数据极大地简化了保持数据一致性所需的模型。

+   **人为容错**：在软件开发生命周期的正常过程中修复或升级软件时，通常需要部署新版本的分析并通过系统重放历史数据以产生修订答案。事实上，在管理直接处理具有此能力的数据的系统时，这通常是至关重要的。批处理层提供了历史数据的持久存储，因此允许恢复任何错误。

正是这些原则构成了它们最终一致的解决方案的基础，而无需担心诸如读取修复或向量时钟之类的复杂性；它们绝对是更友好的开发人员架构！

因此，让我们讨论一些选择一个而不是另一个的原因。让我们首先考虑 Lambda 架构。

## Lambda 架构的重要性

Lambda 架构，最初由 Nathan Marz 提出，通常是这样的：

![Lambda 架构的重要性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_006.jpg)

图 6：Lambda 架构

实质上，数据被双路由到两个层：

+   **批处理层**能够在给定时间点计算快照

+   **实时层**能够处理自上次快照以来的增量更改

**服务层**然后用于将这两个数据视图合并在一起，产生一个最新的真相版本。

除了先前描述的一般特征之外，Lambda 架构在以下特定条件下最适用：

+   复杂或耗时的批量或批处理算法，没有等效或替代的增量迭代算法（并且近似值是不可接受的），因此您需要批处理层。

+   无论系统的并行性如何，批处理层单独无法满足数据一致性的保证，因此您需要实时层。例如，您有：

+   低延迟写入-读取

+   任意宽范围的数据，即年份

+   重数据倾斜

如果您具有以下任一条件之一，您应该考虑使用 Lambda 架构。但是，在继续之前，请注意它带来的可能会带来挑战的以下特性：

+   两个数据管道：批处理和流处理有单独的工作流程，尽管在可能的情况下可以尝试重用核心逻辑和库，但流程本身必须在运行时单独管理。

+   复杂的代码维护：除了简单的聚合之外，批处理和实时层中的算法将需要不同。这对于机器学习算法尤其如此，其中有一个专门研究这一领域的领域，称为在线机器学习（[`en.wikipedia.org/wiki/Online_machine_learning`](https://en.wikipedia.org/wiki/Online_machine_learning)），其中可能涉及实现增量迭代算法或近似算法，超出现有框架之外。

+   服务层中的复杂性增加：为了将增量与聚合合并，服务层中需要进行聚合、联合和连接。工程师们应该小心，不要将其分解为消费系统。

尽管存在这些挑战，Lambda 架构是一种强大而有用的方法，已经成功地在许多机构和组织中实施，包括 Yahoo！、Netflix 和 Twitter。

## Lambda 架构的重要性

Kappa 架构通过将*分布式日志*的概念置于中心，进一步简化了概念。这样可以完全删除批处理层，从而创建一个更简单的设计。Kappa 有许多不同的实现，但通常看起来是这样的：

![Kappa 架构的重要性](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_007.jpg)

图 7：Kappa 架构

在这种架构中，分布式日志基本上提供了数据不可变性和可重放性的特性。通过在处理层引入*可变状态存储*的概念，它通过将所有处理视为流处理来统一计算模型，即使是批处理，也被视为流的特例。当您具有以下特定条件之一时，Kappa 架构最适用：

+   通过增加系统的并行性来减少延迟，可以满足数据一致性的保证。

+   通过实现增量迭代算法可以满足数据一致性的保证

如果这两种选择中的任何一种是可行的，那么 Kappa 架构应该提供一种现代、可扩展的方法来满足您的批处理和流处理需求。然而，值得考虑所选择的任何实现的约束和挑战。潜在的限制包括：

+   精确一次语义：许多流行的分布式消息系统，如 Apache Kafka，目前不支持精确一次消息传递语义。这意味着，目前，消费系统必须处理接收到的数据重复。通常通过使用检查点、唯一键、幂等写入或其他去重技术来完成，但这会增加复杂性，因此使解决方案更难构建和维护。

+   无序事件处理：许多流处理实现，如 Apache Spark，目前不支持按事件时间排序的更新，而是使用处理时间，即系统首次观察到事件的时间。因此，更新可能会无序接收，系统需要能够处理这种情况。同样，这会增加代码复杂性，使解决方案更难构建和维护。

+   没有强一致性，即线性一致性：由于所有更新都是异步应用的，不能保证写入会立即生效（尽管它们最终会一致）。这意味着在某些情况下，您可能无法立即“读取您的写入”。

在下一章中，我们将讨论增量迭代算法，数据倾斜或服务器故障如何影响一致性，以及 Spark Streaming 中的反压特性如何帮助减少故障。关于本节中所解释的内容，我们将按照 Kappa 架构构建我们的分类系统。

# 消费数据流

与批处理作业类似，我们使用`SparkConf`对象和上下文创建一个新的 Spark 应用程序。在流处理应用程序中，上下文是使用批处理大小参数创建的，该参数将用于任何传入的流（GDELT 和 Twitter 层，作为同一上下文的一部分，都将绑定到相同的批处理大小）。由于 GDELT 数据每 15 分钟发布一次，我们的批处理大小自然将是 15 分钟，因为我们希望基于伪实时基础预测类别：

```scala
val sparkConf = new SparkConf().setAppName("GZET")
val ssc = new StreamingContext(sparkConf, Minutes(15))
val sc = ssc.sparkContext
```

## 创建 GDELT 数据流

有许多将外部数据发布到 Spark 流处理应用程序的方法。可以打开一个简单的套接字并开始通过 netcat 实用程序发布数据，或者可以通过监视外部目录的 Flume 代理流式传输数据。生产系统通常使用 Kafka 作为默认代理，因为它具有高吞吐量和整体可靠性（数据被复制到多个分区）。当然，我们可以使用与第十章中描述的相同的 Apache NiFi 堆栈，*故事去重和变异*，但我们想在这里描述一个更简单的路线，即通过 Kafka 主题将文章 URL（从 GDELT 记录中提取）传送到我们的 Spark 应用程序中。

### 创建 Kafka 主题

在测试环境中创建一个新的 Kafka 主题非常容易。在生产环境中，必须特别注意选择正确数量的分区和复制因子。还要注意安装和配置适当的 zookeeper quorum。我们启动 Kafka 服务器并创建一个名为`gzet`的主题，只使用一个分区和一个复制因子：

```scala
$ kafka-server-start /usr/local/etc/kafka/server.properties > /var/log/kafka/kafka-server.log 2>&1 &

$ kafka-topics --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic gzet
```

### 将内容发布到 Kafka 主题

我们可以通过将内容传送到`kafka-console-producer`实用程序来向 Kafka 队列提供数据。我们使用`awk`、`sort`和`uniq`命令，因为我们只对 GDELT 记录中的不同 URL 感兴趣（`URL`是我们的制表符分隔值的最后一个字段，因此是`$NF`）：

```scala
$ cat ${FILE} | awk '{print $NF}' | sort | uniq | kafka-console-producer --broker-list localhost:9092 --topic gzet
```

为了方便起见，我们创建了一个简单的 bash 脚本，用于监听 GDELT 网站上的新文件，下载和提取内容到临时目录，并执行上述命令。该脚本可以在我们的代码存储库（`gdelt-stream.sh`）中找到。

### 从 Spark Streaming 中消费 Kafka

Kafka 是 Spark Streaming 的官方来源，可使用以下依赖项：

```scala
<dependency>
   <groupId>org.apache.spark</groupId>
   <artifactId>spark-streaming-kafka-0-8_2.11</artifactId>
   <version>2.0.0</version>
</dependency>
```

我们定义将用于处理来自 gzet 主题的数据的 Spark 分区数量（这里是 10），以及 zookeeper quorum。我们返回消息本身（传送到我们的 Kafka 生产者的 URL），以构建我们的文章 URL 流：

```scala
def createGdeltStream(ssc: StreamingContext) = {
   KafkaUtils.createStream(
     ssc,
     "localhost:2181",
     "gzet",
     Map("gzet" -> 10)
   ).values
 }

val gdeltUrlStream: DStream[String] = createGdeltStream(ssc)
```

![从 Spark Streaming 中消费 Kafka](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_008.jpg)

图 8：GDELT 在线层

在上图中，我们展示了 GDELT 数据将如何通过监听 Kafka 主题进行批处理。每个批次将被分析，并使用第六章中描述的 HTML 解析器*基于链接的外部数据抓取*下载文章。

## 创建 Twitter 数据流

使用 Twitter 的明显限制是规模的限制。每天有超过 5 亿条推文，我们的应用程序需要以最分布式和可扩展的方式编写，以处理大量的输入数据。此外，即使只有 2%的推文包含对外部 URL 的引用，我们每天仍然需要获取和分析 100 万个 URL（除了来自 GDELT 的数千个 URL）。由于我们没有专门的架构来处理这些数据，因此我们将使用 Twitter 免费提供的 1% firehose。只需在 Twitter 网站上注册一个新应用程序（[`apps.twitter.com`](https://apps.twitter.com)），并检索其关联的应用程序设置和授权令牌。但是请注意，自 Spark Streaming 版本`2.0.0`以来，Twitter 连接器不再是核心 Spark Streaming 的一部分。作为 Apache Bahir 项目的一部分（[`bahir.apache.org/`](http://bahir.apache.org/)），可以使用以下 maven`dependency`：

```scala
<dependency>
   <groupId>org.apache.bahir</groupId>
   <artifactId>spark-streaming-twitter_2.11</artifactId>
   <version>2.0.0</version>
</dependency>
```

因为 Spark Streaming 在后台使用`twitter4j`，所以配置是使用`twitter4j`库中的`ConfigurationBuilder`对象完成的：

```scala
import twitter4j.auth.OAuthAuthorization
import twitter4j.conf.ConfigurationBuilder

def getTwitterConfiguration = {

  val builder = new ConfigurationBuilder()

  builder.setOAuthConsumerKey("XXXXXXXXXXXXXXX")
  builder.setOAuthConsumerSecret("XXXXXXXXXXXX")
  builder.setOAuthAccessToken("XXXXXXXXXXXXXXX")
  builder.setOAuthAccessTokenSecret("XXXXXXXXX")

  val configuration = builder.build()
  Some(new OAuthAuthorization(configuration))

}
```

我们通过提供一个关键字数组（可以是特定的标签）来创建我们的数据流。在我们的情况下，我们希望收听所有 1%，无论使用哪些关键字或标签（发现新标签实际上是我们应用程序的一部分），因此提供一个空数组：

```scala
def createTwitterStream(ssc: StreamingContext) = {
   TwitterUtils.createStream(
     ssc,
     getTwitterConfiguration,
     Array[String]()
   )
}

val twitterStream: DStream[Status] = createTwitterStream(ssc)
getText method that returns the tweet body:
```

```scala
val body: String = status.getText()
val user: User = status.getUser()
val contributors: Array[Long] = status.getContributors()
val createdAt: Long = status.getCreatedAt()
../..
```

# 处理 Twitter 数据

使用 Twitter 的第二个主要限制是噪音的限制。当大多数分类模型针对数十个不同的类进行训练时，我们将针对每天数十万个不同的标签进行工作。我们只关注热门话题，即在定义的批处理窗口内发生的热门话题。然而，由于 Twitter 上的 15 分钟批处理大小不足以检测趋势，因此我们将应用一个 24 小时的移动窗口，其中将观察和计数所有标签，并仅保留最受欢迎的标签。

![处理 Twitter 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_009.jpg)

图 9：Twitter 在线层，批处理和窗口大小

使用这种方法，我们减少了不受欢迎标签的噪音，使我们的分类器更加准确和可扩展，并显著减少了要获取的文章数量，因为我们只关注与热门话题一起提及的流行 URL。这使我们能够节省大量时间和资源，用于分析与分类模型无关的数据。

## 提取 URL 和标签

我们提取干净的标签（长度超过 x 个字符且不包含数字；这是减少噪音的另一种措施）和对有效 URL 的引用。请注意 Scala 的`Try`方法，它在测试`URL`对象时捕获任何异常。只有符合这两个条件的推文才会被保留：

```scala
def extractTags(tweet: String) = {
  StringUtils.stripAccents(tweet.toLowerCase())
    .split("\\s")
    .filter { word =>
      word.startsWith("#") &&
        word.length > minHashTagLength &&
        word.matches("#[a-z]+")
    }
}

def extractUrls(tweet: String) = {
  tweet.split("\\s")
    .filter(_.startsWith("http"))
    .map(_.trim)
    .filter(url => Try(new URL(url)).isSuccess)
}

def getLabeledUrls(twitterStream: DStream[Status]) = {
  twitterStream flatMap { tweet =>
    val tags = extractTags(tweet.getText)
    val urls = extractUrls(tweet.getText)
    urls map { url =>
      (url, tags)
    }
  }
}

val labeledUrls = getLabeledUrls(twitterStream)
```

## 保留热门标签

这一步的基本思想是在 24 小时的时间窗口内执行一个简单的词频统计。我们提取所有的标签，赋予一个值为 1，并使用 reduce 函数计算出现次数。在流处理上，`reduceByKey`函数可以使用`reduceByKeyAndWindow`方法在一个窗口上应用（必须大于批处理大小）。尽管这个词频字典在每个批处理中都是可用的，但当前的前十个标签每 15 分钟打印一次，数据将在一个较长的时间段（24 小时）内计数：

```scala
def getTrends(twitterStream: DStream[Status]) = {

  val stream = twitterStream
    .flatMap { tweet =>
      extractTags(tweet.getText)
    }
    .map(_ -> 1)
    .reduceByKeyAndWindow(_ + _, Minutes(windowSize))

  stream.foreachRDD { rdd =>
    val top10 = rdd.sortBy(_._2, ascending = false).take(10)
    top10.foreach { case (hashTag, count) =>
      println(s"[$hashTag] - $count")
    }
  }

  stream
}

val twitterTrend = getTrends(twitterStream)
```

在批处理上下文中，可以轻松地将标签的 RDD 与 Twitter RDD 连接，以保留只有“最热门”推文（提及与热门标签一起的文章的推文）。在流处理上下文中，数据流不能连接，因为每个流包含多个 RDD。相反，我们使用`transformWith`函数将一个`DStream`与另一个`DStream`进行转换，该函数接受一个匿名函数作为参数，并在它们的每个 RDD 上应用它。我们通过应用一个过滤不受欢迎推文的函数，将我们的 Twitter 流与我们的标签流进行转换。请注意，我们使用 Spark 上下文广播我们当前的前 n 个标签（在这里限制为前 100 个）：

```scala
val joinFunc = (labeledUrls: RDD[(String, Array[String])], twitterTrend: RDD[(String, Int)]) => {

   val sc = twitterTrend.sparkContext
   val leaderBoard = twitterTrend
     .sortBy(_._2, ascending = false)
     .take(100)
     .map(_._1)

   val bLeaderBoard = sc.broadcast(leaderBoard)

   labeledUrls
     .flatMap { case (url, tags) =>
       tags map (tag => (url, tag))
     }
     .filter { case (url, tag) =>
       bLeaderBoard.value.contains(tag)
     }
     .groupByKey()
     .mapValues(_.toArray.distinct)

 }

 val labeledTrendUrls = labeledUrls
   .transformWith(twitterTrend, joinFunc)
```

因为返回的流将只包含“最热门”的 URL，所以数据量应该大大减少。虽然在这个阶段我们无法保证 URL 是否指向正确的文本内容（可能是 YouTube 视频或简单的图片），但至少我们知道我们不会浪费精力获取与无用主题相关的内容。

## 扩展缩短的 URL

Twitter 上的 URL 是缩短的。以编程方式检测真实来源的唯一方法是为所有 URL“打开盒子”，可悲的是，这浪费了大量的时间和精力，可能是无关紧要的内容。值得一提的是，许多网络爬虫无法有效地处理缩短的 URL（包括 Goose 爬虫）。我们通过打开 HTTP 连接、禁用重定向并查看`Location`头来扩展 URL。我们还为该方法提供了一个“不受信任”的来源列表，这些来源对于分类模型的上下文来说并没有提供任何有用的内容（例如来自[`www.youtube.com`](https://www.youtube.com)的视频）：

```scala
def expandUrl(url: String) : String = {

  var connection: HttpURLConnection = null
  try {

    connection = new URL(url)
                    .openConnection
                    .asInstanceOf[HttpURLConnection]

    connection.setInstanceFollowRedirects(false)
    connection.setUseCaches(false)
    connection.setRequestMethod("GET")
    connection.connect()

    val redirectedUrl = connection.getHeaderField("Location")

    if(StringUtils.isNotEmpty(redirectedUrl)){
       redirectedUrl
     } else {
       url
     }

   } catch {
     case e: Throwable => url
   } finally {
     if(connection != null)
       connection.disconnect()
   }
 }

 def expandUrls(tStream: DStream[(String, Array[String])]) = {
   tStream
     .map { case (url, tags) =>
       (HtmlHandler.expandUrl(url), tags)
     }
     .filter { case (url, tags) =>
       !untrustedSources.value.contains(url)
     }
}

val expandedUrls = expandUrls(labeledTrendUrls)
```

### 提示

与上一章中所做的类似，我们彻底捕捉由 HTTP 连接引起的任何可能的异常。任何未捕获的异常（可能是一个简单的 404 错误）都会使这个任务在引发致命异常之前重新评估不同的 Spark 执行器，退出我们的 Spark 应用程序。

# 获取 HTML 内容

我们已经在上一章介绍了网络爬虫，使用了为 Scala 2.11 重新编译的 Goose 库。我们将创建一个以`DStream`作为输入的方法，而不是 RDD，并且只保留至少 500 个单词的有效文本内容。最后，我们将返回一个文本流以及相关的标签（热门的标签）。

```scala
def fetchHtmlContent(tStream: DStream[(String, Array[String])]) = {

  tStream
    .reduceByKey(_++_.distinct)
    .mapPartitions { it =>

      val htmlFetcher = new HtmlHandler()
      val goose = htmlFetcher.getGooseScraper
      val sdf = new SimpleDateFormat("yyyyMMdd")

      it.map { case (url, tags) =>
        val content = htmlFetcher.fetchUrl(goose, url, sdf)
        (content, tags)
      }
      .filter { case (contentOpt, tags) =>
        contentOpt.isDefined &&
          contentOpt.get.body.isDefined &&
          contentOpt.get.body.get.split("\\s+").length >= 500
      }
      .map { case (contentOpt, tags) =>
        (contentOpt.get.body.get, tags)
      }

}

val twitterContent = fetchHtmlContent(expandedUrls)
```

我们对 GDELT 数据应用相同的方法，其中所有内容（文本、标题、描述等）也将被返回。请注意`reduceByKey`方法，它充当我们数据流的一个不同函数：

```scala
def fetchHtmlContent(urlStream: DStream[String]) = {

  urlStream
    .map(_ -> 1)
    .reduceByKey()
    .keys
    .mapPartitions { urls =>

      val sdf = new SimpleDateFormat("yyyyMMdd")
      val htmlHandler = new HtmlHandler()
      val goose = htmlHandler.getGooseScraper
      urls.map { url =>
         htmlHandler.fetchUrl(goose, url, sdf)
      }

    }
    .filter { content =>
      content.isDefined &&
        content.get.body.isDefined &&
        content.get.body.get.split("\\s+").length > 500
    }
    .map(_.get)
}

val gdeltContent = fetchHtmlContent(gdeltUrlStream)
```

# 使用 Elasticsearch 作为缓存层

我们的最终目标是在每个批处理（每 15 分钟）中训练一个新的分类器。然而，分类器将使用不仅仅是我们在当前批次中下载的少数记录。我们不知何故必须在较长时间内缓存文本内容（设置为 24 小时），并在需要训练新分类器时检索它。考虑到 Larry Wall 的引用，我们将尽可能懒惰地维护在线层上的数据一致性。基本思想是使用**生存时间**（**TTL**）参数，它将无缝地丢弃任何过时的记录。Cassandra 数据库提供了这个功能（HBase 或 Accumulo 也是如此），但 Elasticsearch 已经是我们核心架构的一部分，可以轻松用于此目的。我们将为`gzet`/`twitter`索引创建以下映射，并启用`_ttl`参数：

```scala
$ curl -XPUT 'http://localhost:9200/gzet'
$ curl -XPUT 'http://localhost:9200/gzet/_mapping/twitter' -d '
{
    "_ttl" : {
           "enabled" : true
    },
    "properties": {
      "body": {
        "type": "string"
      },
      "time": {
        "type": "date",
        "format": "yyyy-MM-dd HH:mm:ss"
      },
      "tags": {
        "type": "string",
        "index": "not_analyzed"
      },
      "batch": {
        "type": "integer"
      }
    }
}'
```

我们的记录将在 Elasticsearch 上存在 24 小时（TTL 值在插入时定义），之后任何记录将被简单丢弃。由于我们将维护任务委托给 Elasticsearch，我们可以安全地从在线缓存中拉取所有可能的记录，而不用太担心任何过时的值。所有检索到的数据将用作我们分类器的训练集。高层过程如下图所示：

![使用 Elasticsearch 作为缓存层](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_010.jpg)

图 10：使用 Elasticsearch 作为缓存层

对于数据流中的每个 RDD，我们从前 24 小时中检索所有现有记录，缓存我们当前的 Twitter 内容，并训练一个新的分类器。将数据流转换为 RDD 是使用`foreachRDD`函数的简单操作。

我们使用 Elasticsearch API 中的`saveToEsWithMeta`函数将当前记录持久化到 Elasticsearch 中。此函数接受`TTL`参数作为元数据映射的一部分（设置为 24 小时，以秒为单位，并格式化为字符串）：

```scala
import org.elasticsearch.spark._
import org.elasticsearch.spark.rdd.Metadata._

def saveCurrentBatch(twitterContent: RDD[(String, Array[String])]) = {
  twitterContent mapPartitions { it =>
    val sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    it map { case (content, tags) =>
      val data = Map(
        "time" -> sdf.format(new Date()),
        "body" -> content,
        "tags" -> tags
      )
      val metadata = Map(
        TTL -> "172800s"
      )
      (metadata, data)
     }
   } saveToEsWithMeta "gzet/twitter"
 }
```

值得在 Elasticsearch 上执行简单的检查，以确保`TTL`参数已经正确设置，并且每秒都在有效减少。一旦达到 0，索引的文档应该被丢弃。以下简单命令每秒打印出文档 ID [`AVRr9LaCoYjYhZG9lvBl`] 的`_ttl`值。这使用一个简单的`jq`实用程序（[`stedolan.github.io/jq/download`](https://stedolan.github.io/jq/download)/）从命令行解析 JSON 对象：

```scala
$ while true ; do TTL=`curl -XGET 'http://localhost:9200/gzet/twitter/AVRr9LaCoYjYhZG9lvBl' 2>/dev/null | jq "._ttl"`; echo "TTL is $TTL"; sleep 1; done

../..
TTL is 48366081
TTL is 48365060
TTL is 48364038
TTL is 48363016
../..
```

可以使用以下函数将所有在线记录（具有未过期 TTL 的记录）检索到 RDD 中。与我们在第七章中所做的类似，*构建社区*，使用 JSON 解析从 Elasticsearch 中提取列表比使用 Spark DataFrame 要容易得多：

```scala
import org.elasticsearch.spark._
import org.json4s.DefaultFormats
import org.json4s.jackson.JsonMethods._

def getOnlineRecords(sc: SparkContext) = {
  sc.esJsonRDD("gzet/twitter").values map { jsonStr =>
    implicit val format = DefaultFormats
     val json = parse(jsonStr)
     val tags = (json \ "tags").extract[Array[String]]
     val body = (json \ "body").extract[String]
     (body, tags)
   }
 }
```

我们从缓存层下载所有 Twitter 内容，同时保存我们当前的批处理。剩下的过程是训练我们的分类算法。这个方法在下一节中讨论：

```scala
twitterContent foreachRDD { batch =>

  val sc = batch.sparkContext 
  batch.cache()

  if(batch.count() > 0) {
    val window = getOnlineRecords(sc)
    saveCurrentBatch(batch)
    val trainingSet = batch.union(window)
    //Train method described hereafter
    trainAndSave(trainingSet, modelOutputDir)
  }

  batch.unpersist(blocking = false)
}
```

# 分类数据

我们应用的剩余部分是开始对数据进行分类。如前所介绍的，使用 Twitter 的原因是从外部资源中窃取地面真相。我们将使用 Twitter 数据训练一个朴素贝叶斯分类模型，同时预测 GDELT URL 的类别。使用 Kappa 架构方法的便利之处在于，我们不必太担心在不同应用程序或不同环境之间导出一些常见的代码。更好的是，我们不必在批处理层和速度层之间导出/导入我们的模型（GDELT 和 Twitter，共享相同的 Spark 上下文，都是同一物理层的一部分）。我们可以将我们的模型保存到 HDFS 以进行审计，但我们只需要在两个类之间传递一个 Scala 对象的引用。

## 训练朴素贝叶斯模型

我们已经介绍了使用 Stack Exchange 数据集引导朴素贝叶斯模型的概念，以及使用`分类器`对象从文本内容构建`LabeledPoints`。我们将创建一个`ClassifierModel` case 类，它包装了朴素贝叶斯模型及其相关的标签字典，并公开了`predict`和`save`方法：

```scala
case class ClassifierModel(
  model: NaiveBayesModel,
  labels: Map[String, Double]
) {

   def predictProbabilities(vectors: RDD[Vector]) = {
     val sc = vectors.sparkContext
     val bLabels = sc.broadcast(labels.map(_.swap))
     model.predictProbabilities(vectors).map { vector =>
       bLabels.value
         .toSeq
         .sortBy(_._1)
         .map(_._2)
         .zip(vector.toArray)
         .toMap
     }
   }

   def save(sc: SparkContext, outputDir: String) = {
     model.save(sc, s"$outputDir/model")
     sc.parallelize(labels.toSeq)
       .saveAsObjectFile(s"$outputDir/labels")
   }

}
```

因为可能需要多个标签来完全描述一篇文章的内容，所以我们将使用`predictProbabilities`函数来预测概率分布。我们使用保存在模型旁边的标签字典将我们的标签标识符（作为`Double`）转换为原始类别（作为`String`）。最后，我们可以将我们的模型和标签字典保存到 HDFS，仅供审计目的。

### 提示

所有 MLlib 模型都支持保存和加载功能。数据将以`ObjectFile`的形式持久化在 HDFS 中，并且可以轻松地检索和反序列化。使用 ML 库，对象被保存为 parquet 格式。然而，需要保存额外的信息；例如在我们的例子中，用于训练该模型的标签字典。

## 线程安全

我们的`分类器`是一个单例对象，根据单例模式，应该是线程安全的。这意味着并行线程不应该使用相同的状态进行修改，例如使用 setter 方法。在我们当前的架构中，只有 Twitter 每 15 分钟训练和更新一个新模型，这些模型将只被 GDELT 服务使用（没有并发更新）。然而，有两件重要的事情需要考虑：

1.  首先，我们的模型是使用不同的标签进行训练的（在 24 小时时间窗口内找到的标签，每 15 分钟提取一次）。新模型将根据更新的字典进行训练。模型和标签都是紧密耦合的，因此必须同步。在 GDELT 在 Twitter 更新模型时拉取标签的不太可能事件中，我们的预测将是不一致的。我们通过将标签和模型都包装在同一个`ClassifierModel` case 类中来确保线程安全。

1.  第二个（虽然不太关键）问题是我们的过程是并行的。这意味着相似的任务将同时从不同的执行器上执行，处理不同的数据块。在某个时间点，我们需要确保每个执行器上的所有模型都是相同版本的，尽管使用略旧的模型预测特定数据块仍然在技术上是有效的（只要模型和标签是同步的）。我们用以下两个例子来说明这个说法。第一个例子无法保证执行器之间模型的一致性：

```scala
val model = NaiveBayes.train(points)
vectors.map { vector =>
  model.predict(vector)
 }
```

第二个例子（Spark 默认使用）将模型广播到所有执行器，从而保证预测阶段的整体一致性：

```scala
val model = NaiveBayes.train(points)
val bcModel = sc.broadcast(model)
vectors mapPartitions { it =>
  val model = bcModel.value
  it.map { vector =>
    model.predict(vector)
  }
}
```

在我们的`分类器`单例对象中，我们将我们的模型定义为一个全局变量（因为它可能还不存在），在每次调用`train`方法后将更新该模型：

```scala
var model = None: Option[ClassifierModel]

def train(rdd: RDD[(String, Array[String])]): ClassifierModel = {
  val labeledPoints = buildLabeledPoints(rdd)
  val labels = getLabels(rdd)
  labeledPoints.cache()
  val nbModel = NaiveBayes.train(labeledPoints)
  labeledPoints.unpersist(blocking = false)
  val cModel = ClassifierModel(nbModel, labels)
  model = Some(cModel)
  cModel
}
```

回到我们的 Twitter 流，对于每个 RDD，我们构建我们的训练集（在我们的`分类器`中抽象出来），训练一个新模型，然后将其保存到 HDFS：

```scala
def trainAndSave(trainingSet: RDD[(String, Array[String])],  modelOutputDir: String) = {
  Classifier
     .train(trainingSet)
     .save(batch.sparkContext, modelOutputDir)
}
```

## 预测 GDELT 数据

使用`分类器`单例对象，我们可以访问 Twitter 处理器发布的最新模型。对于每个 RDD，对于每篇文章，我们只需预测描述每篇文章文本内容的标签概率分布：

```scala
gdeltContent.foreachRDD { batch =>

  val textRdd = batch.map(_.body.get)
  val predictions = Classifier.predictProbabilities(textRdd)

  batch.zip(predictions).map { case (content, dist) =>
    val hashTags = dist.filter { case (hashTag, proba) =>
      proba > 0.25d
    }
    .toSeq
    .map(_._1)
    (content, hashTags)
  }
  .map { case (content, hashTags) =>
    val sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    Map(
      "time"  -> sdf.format(new Date()),
      "body"  -> content.body.get,
      "url"   -> content.url,
      "tags"  -> hashTags,
      "title" -> content.title
    )
  }
  .saveToEs("gzet/gdelt")

}
```

我们只保留高于 25%的概率，并将每篇文章与其预测的标签一起发布到我们的 Elasticsearch 集群。发布结果正式标志着我们分类应用的结束。我们在这里报告完整的架构：

![预测 GDELT 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_011.jpg)

图 11：标记新闻文章的创新方式

# 我们的 Twitter 机械土耳其

分类算法的准确性应该根据测试数据集来衡量，即在训练阶段未包含的标记数据集。我们无法访问这样的数据集（这是我们最初引导模型的原因），因此我们无法比较原始与预测的类别。我们可以通过可视化我们的结果来估计整体置信水平，而不是真实的准确性。有了我们在 Elasticsearch 上的所有数据，我们构建了一个 Kibana 仪表板，并增加了一个用于标签云可视化的插件（[`github.com/stormpython/tagcloud`](https://github.com/stormpython/tagcloud)）。

下图显示了在 2016 年 5 月 1 日分析和预测的 GDELT 文章数量。在不到 24 小时内下载了大约 18000 篇文章（每 15 分钟一个批次）。在每个批次中，我们观察到不超过 100 个不同的预测标签；这是幸运的，因为我们只保留了在 24 小时时间窗口内出现的前 100 个热门标签。此外，它给了我们一些关于 GDELT 和 Twitter 遵循相对正常分布的线索（批次不会围绕特定类别偏斜）。

![我们的 Twitter 机械土耳其](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_012.jpg)

图 12：预测文章于 5 月 1 日

除了这 18000 篇文章，我们还提取了大约 700 条 Twitter 文本内容，标记了我们 100 个热门标签，平均每个主题被七篇文章覆盖。尽管这个训练集已经是本书内容的一个良好开端，但我们可能可以通过在内容方面放宽限制或将类似的标签分组成更广泛的类别来扩展它。我们还可以增加 Elasticsearch 上的 TTL 值。增加观察数量同时限制 Twitter 噪音肯定会提高整体模型的准确性。

观察到在特定时间窗口内最流行的标签是[#mayday]和[#trump]。我们还观察到至少与[#maga]一样多的[#nevertrump]，因此满足了美国两个政党的要求。这将在第十一章中使用美国选举数据进行确认，*情感分析异常检测*。

最后，我们选择一个特定的标签并检索其所有相关关键词。这很重要，因为它基本上验证了我们分类算法的一致性。我们希望对于来自 Twitter 的每个标签，来自 GDELT 的重要术语足够一致，并且应该都与相同的标签含义相关。我们关注[**#trump**]标签，并在下图中访问特朗普云：

![我们的 Twitter 机械土耳其](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_09_013.jpg)

图 13：#特朗普云

我们观察到大多数重要术语（每篇文章预测为[**#trump**]）都与总统竞选、美国、初选等有关。它还包含了参加总统竞选的候选人的名字（希拉里·克林顿和特德·克鲁兹）。尽管我们仍然发现一些与唐纳德·特朗普无关的文章和关键词，但这验证了我们算法的一定一致性。对于许多记录（超过 30%），结果甚至超出了我们最初的期望。

# 总结

尽管我们对许多整体模型的一致性印象深刻，但我们意识到我们肯定没有构建最准确的分类系统。将这项任务交给数百万用户是一项雄心勃勃的任务，绝对不是获得明确定义的类别的最简单方式。然而，这个简单的概念验证向我们展示了一些重要的东西：

1.  它在技术上验证了我们的 Spark Streaming 架构。

1.  它验证了我们使用外部数据集引导 GDELT 的假设。

1.  它让我们变得懒惰、不耐烦和骄傲。

1.  它在没有任何监督的情况下学习，并且在每个批次中最终变得更好。

没有数据科学家可以在短短几周内构建一个完全功能且高度准确的分类系统，尤其是在动态数据上；一个合适的分类器需要至少在最初的几个月内进行评估、训练、重新评估、调整和重新训练，然后至少每半年进行一次重新评估。我们的目标是描述实时机器学习应用中涉及的组件，并帮助数据科学家锐化他们的创造力（跳出常规思维是现代数据科学家的首要美德）。

在下一章中，我们将专注于文章变异和故事去重；一个话题随着时间的推移有多大可能会发展，一个人群（或社区）有多大可能会随时间变异？通过将文章去重为故事，故事去重为史诗，我们能否根据先前的观察来预测可能的结果？


# 第十章：故事去重和变异

全球网络有多大？虽然几乎不可能知道确切的大小 - 更不用说深网和暗网了 - 但据估计，2008 年它的页面数量超过了一万亿，那在数据时代，有点像中世纪。将近十年后，可以肯定地假设互联网的集体大脑比我们实际的灰质在我们的*耳朵*之间更多。但在这万亿以上的 URL 中，有多少网页是真正相同的，相似的，或者涵盖相同的主题？

在本章中，我们将对 GDELT 数据库进行去重和索引，然后，我们将随时间跟踪故事，并了解它们之间的联系，它们可能如何变异，以及它们是否可能导致不久的将来发生任何后续事件。

我们将涵盖以下主题：

+   了解*Simhash*的概念以检测近似重复

+   构建在线去重 API

+   使用 TF-IDF 构建向量，并使用*随机索引*减少维度

+   使用流式 KMeans 实时构建故事连接

# 检测近似重复

虽然本章是关于将文章分组成故事，但这一节是关于检测近似重复。在深入研究去重算法之前，值得介绍一下在新闻文章的背景下故事和去重的概念。给定两篇不同的文章 - 通过不同的 URL 我们指的是两个不同的 URL - 我们可能会观察到以下情况：

+   文章 1 的 URL 实际上重定向到文章 2，或者是文章 2 中提供的 URL 的扩展（例如一些额外的 URL 参数，或者缩短的 URL）。尽管它们的 URL 不同，但具有相同内容的两篇文章被视为*真正的重复*。

+   文章 1 和文章 2 都涵盖了完全相同的事件，但可能由两个不同的出版商撰写。它们有很多共同的内容，但并不真正相似。根据下文解释的某些规则，它们可能被视为*近似重复*。

+   文章 1 和文章 2 都涵盖了相同类型的事件。我们观察到风格上的主要差异或相同主题的不同*风味*。它们可以被归为一个共同的*故事*。

+   文章 1 和文章 2 涵盖了两个不同的事件。两篇内容是*不同*的，不应该被归为同一个故事，也不应该被视为近似重复。

Facebook 用户一定注意到了*相关文章*功能。当你喜欢一篇新闻文章 - 点击一篇文章的链接或播放一篇文章的视频时，Facebook 认为这个链接很有趣，并更新其时间线（或者称之为）以显示更多看起来相似的内容。在*图 1*中，我真的很惊讶地看到三星 Galaxy Note 7 智能手机冒烟或着火，因此被大部分美国航班禁止。Facebook 自动为我推荐了这个三星惨案周围的类似文章。可能发生的事情是，通过打开这个链接，我可能已经查询了 Facebook 内部 API，并要求相似的内容。这就是实时查找近似重复的概念，这也是我们将在第一节中尝试构建的内容。

![检测近似重复](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_001.jpg)

图 1：Facebook 推荐相关文章

## 哈希处理的第一步

查找真正的重复很容易。如果两篇文章的内容相同，它们将被视为相同。但是，我们可以比较它们的哈希值，而不是比较字符串（可能很大，因此不高效）；就像比较手写签名一样；具有相同签名的两篇文章应被视为相同。如下所示，一个简单的`groupBy`函数将从字符串数组中检测出真正的重复：

```scala
Array("Hello Spark", "Hello Hadoop", "Hello Spark")
  .groupBy(a => Integer.toBinaryString(a.hashCode))
  .foreach(println)

11001100010111100111000111001111 List(Hello Spark, Hello Spark)
10101011110110000110101101110011 List(Hello Hadoop)
```

但即使是最复杂的哈希函数也会导致一些碰撞。Java 内置的`hashCode`函数将字符串编码为 32 位整数，这意味着理论上，我们只有 2³²种可能性可以得到相同哈希值的不同单词。实际上，碰撞应该始终小心处理，因为根据*生日悖论*，它们会比 2³²的值更频繁地出现。为了证明我们的观点，以下示例认为四个不同的字符串是相同的：

```scala
Array("AaAa", "BBBB", "AaBB", "BBAa")
  .groupBy(a => Integer.toBinaryString(a.hashCode))
  .foreach(Sprintln)

11111000000001000000 List(AaAa, BBBB, AaBB, BBAa)
```

此外，有些文章有时可能只是在很小的文本部分上有所不同，例如广告片段、额外的页脚或 HTML 代码中的额外位，这使得哈希签名与几乎相同的内容不同。事实上，即使一个单词有一个小的拼写错误，也会导致完全不同的哈希值，使得两篇近似重复的文章被认为是完全不同的。

```scala
Array("Hello, Spark", "Hello Spark")
  .groupBy(a => Integer.toBinaryString(a.hashCode))
  .foreach(println)

11100001101000010101000011010111  List(Hello, Spark)
11001100010111100111000111001111  List(Hello Spark)
```

尽管字符串`Hello Spark`和`Hello, Spark`非常接近（它们只相差一个字符），它们的哈希值相差 16 位（32 位中的 16 位）。幸运的是，互联网的长者们可能已经找到了使用哈希值来检测近似重复内容的解决方案。

## 站在互联网巨头的肩膀上

不用说，谷歌在索引网页方面做得相当不错。拥有超过一万亿个不同的 URL，检测重复内容是索引网页内容时的关键。毫无疑问，互联网巨头们多年来一定已经开发出了解决这个规模问题的技术，从而限制了索引整个互联网所需的计算资源。这里描述的其中一种技术称为*Simhash*，它非常简单、整洁，但效率很高，如果你真的想要*精通数据科学的 Spark*，那么了解它是值得的。

### 注意

关于*Simhash*的更多信息可以在[`www.wwwconference.org/www2007/papers/paper215.pdf`](http://www.wwwconference.org/www2007/papers/paper215.pdf)找到。

### Simhashing

**Simhash**的主要思想不是一次计算一个单一的哈希值，而是查看文章的内容并计算多个单独的哈希值。对于每个单词，每对单词，甚至每个两个字符的 shingle，我们都可以使用前面描述的简单的 Java 内置`hashCode`函数轻松计算哈希值。在下面的*图 2*中，我们报告了字符串**hello simhash**中包含的两个字符集的所有 32 位哈希值（省略了前 20 个零值）：

![Simhashing](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_02-1.jpg)

图 2：构建 hello simhash shingles

接下来报告了一个简单的 Scala 实现：

```scala
def shingles(content: String) = {
  content.replaceAll("\\s+", "")
    .sliding(2)
    .map(s => s.mkString(""))
    .map(s => (s, s.hashCode)) 
}

implicit class BitOperations(i1: Int) {
  def toHashString: String = {
    String.format(
      "%32s",
      Integer.toBinaryString(i1)
    ).replace(" ", "0")
  }
}

shingles("spark").foreach { case (shingle, hash) =>
  println("[" + shingle + "]\t" + hash.toHashString)
}

[sp]  00000000000000000000111001011101
[pa]  00000000000000000000110111110001
[ar]  00000000000000000000110000110001
[rk]  00000000000000000000111000111001
```

计算了所有这些哈希值后，我们将一个`Simhash`对象初始化为零整数。对于 32 位整数中的每个位，我们计算具有该特定位设置为 1 的哈希值的数量，并减去具有该列表中具有该特定位未设置的值的数量。这给我们提供了*图 3*中报告的数组。最后，任何大于 0 的值都将设置为 1，任何小于或等于 0 的值都将保留为 0。这里唯一棘手的部分是进行位移操作，但算法本身相当简单。请注意，我们在这里使用递归来避免使用可变变量（使用`var`）或列表。

![Simhashing](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_03.jpg)

图 3：构建 hello simhash

```scala
implicit class BitOperations(i1: Int) {

  // ../.. 

  def isBitSet(bit: Int): Boolean = {
    ((i1 >> bit) & 1) == 1
  }
}

implicit class Simhash(content: String) {

  def simhash = {
    val aggHash = shingles(content).flatMap{ hash =>
      Range(0, 32).map { bit =>
        (bit, if (hash.isBitSet(bit)) 1 else -1)
      }
    }
    .groupBy(_._1)
    .mapValues(_.map(_._2).sum > 0)
    .toArray

    buildSimhash(0, aggHash)
  }

 private def buildSimhash(
      simhash: Int,
      aggBit: Array[(Int, Boolean)]
     ): Int = {

    if(aggBit.isEmpty) return simhash
    val (bit, isSet) = aggBit.head
    val newSimhash = if(isSet) {
      simhash | (1 << bit)
    } else {
      simhash
    }
    buildSimhash(newSimhash, aggBit.tail)

  }
}

val s = "mastering spark for data science"
println(toHashString(s.simhash))

00000000000000000000110000110001
```

### 汉明重量

很容易理解，两篇文章共有的单词越多，它们的 Simhash 中都会有一个相同的位*b*设置为 1。但 Simhash 的美妙之处在于聚合步骤。我们语料库中的许多其他单词（因此其他哈希）可能没有设置这个特定的位*b*，因此当观察到一些不同的哈希时，这个值也会减少。共享一组共同的单词是不够的，相似的文章还必须共享相同的词频。以下示例显示了为字符串**hello simhash**、**hello minhash**和**hello world**计算的三个 Simhash 值。

![汉明重量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_04.jpg)

图 4：比较 hello simhash

当**hello simhash**和**hello world**之间的差异为 3 位时，**hello simhash**和**hello minhash**之间的差异只有**1**。实际上，我们可以将它们之间的距离表示为它们的异或（**XOR**）积的汉明重量。**汉明重量**是我们需要改变的位数，以将给定数字转换为零元素。因此，两个数字的**XOR**操作的汉明重量是这两个元素之间不同的位数，这种情况下是**1**。

![汉明重量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_05.jpg)

图 5：hello simhash 的汉明重量

我们简单地使用 Java 的`bitCount`函数，该函数返回指定整数值的二进制补码表示中的一位数。

```scala
implicit class BitOperations(i1: Int) {

  // ../..

  def distance(i2: Int) = {
    Integer.bitCount(i1 ^ i2) 
  }
}

val s1 = "hello simhash"
val s2 = "hello minhash"
val dist = s1.simhash.distance(s2.simhash)
```

我们已经成功构建了 Simhash 并进行了一些简单的成对比较。下一步是扩展规模并开始从 GDELT 数据库中检测实际的重复项。

## 在 GDELT 中检测近似重复项

我们在第二章中深入讨论了数据获取过程，*数据采集*。对于这个用例，我们将使用图 6 中的 NiFi 流，该流监听 GDELT 主 URL，获取并解压最新的 GKG 存档，并以压缩格式将此文件存储在 HDFS 中。

![在 GDELT 中检测近似重复项](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_006.jpg)

图 6：下载 GKG 数据

我们首先使用我们之前创建的一组解析器（在我们的 GitHub 存储库中可用）解析我们的 GKG 记录，提取所有不同的 URL 并使用第六章中介绍的 Goose 提取器获取 HTML 内容，*抓取基于链接的外部数据*。

```scala
val gdeltInputDir = args.head
val gkgRDD = sc.textFile(gdeltInputDir)
  .map(GKGParser.toJsonGKGV2)
  .map(GKGParser.toCaseClass2)

val urlRDD = gkgRDD.map(g => g.documentId.getOrElse("NA"))
  .filter(url => Try(new URL(url)).isSuccess)
  .distinct()
  .repartition(partitions)

val contentRDD = urlRDD mapPartitions { it =>
  val html = new HtmlFetcher()
  it map html.fetch
}
```

因为`hashcode`函数是区分大小写的（*Spark*和*spark*会产生完全不同的哈希值），强烈建议在`simhash`函数之前清理文本。与第九章中描述的类似，我们首先使用以下 Lucene 分析器来词干化单词：

```scala
<dependency>
  <groupId>org.apache.lucene</groupId>
  <artifactId>lucene-analyzers-common</artifactId>
  <version>4.10.1</version>
</dependency>
```

正如您可能早些时候注意到的，我们在一个隐式类中编写了我们的 Simhash 算法；我们可以使用以下导入语句直接在字符串上应用我们的`simhash`函数。在开发的早期阶段付出额外的努力总是值得的。

```scala
import io.gzet.story.simhash.SimhashUtils._
val simhashRDD = corpusRDD.mapValues(_.simhash)
```

现在我们有了一个内容的 RDD（`Content`是一个包装文章 URL、标题和正文的案例类），以及它的 Simhash 值和一个稍后可能使用的唯一标识符。让我们首先尝试验证我们的算法并找到我们的第一个重复项。从现在开始，我们只考虑在它们的 32 位 Simhash 值中最多有 2 位差异的文章作为重复项。

```scala
hamming match {
  case 0 => // identical articles - true-duplicate
  case 1 => // near-duplicate (mainly typo errors)
  case 2 => // near-duplicate (minor difference in style)
  case _ => // different articles
}
```

但这里出现了一个可伸缩性挑战：我们肯定不想执行笛卡尔积来比较 Simhash RDD 中的成对文章。相反，我们希望利用 MapReduce 范式（使用`groupByKey`函数）并且只对重复的文章进行分组。我们的方法遵循*扩展和征服*模式，首先扩展我们的初始数据集，利用 Spark shuffle，然后在执行器级别解决我们的问题。因为我们只需要处理 1 位差异（然后我们将对 2 位应用相同的逻辑），所以我们的策略是扩展我们的 RDD，以便对于每个 Simhash`s`，我们使用相同的 1 位掩码输出所有其他 31 个 1 位组合。

```scala
def oneBitMasks: Set[Int] = {
  (0 to 31).map(offset => 1 << offset).toSet
}

00000000000000000000000000000001
00000000000000000000000000000010
00000000000000000000000000000100
00000000000000000000000000001000
...
```

对于 Simhash 值`s`，我们使用每个前置掩码和 Simhash 值`s`之间的 XOR 输出可能的 1 位组合。

```scala
val s = 23423
oneBitMasks foreach { mask =>
  println((mask ^ s).toHashString)
}

00000000000000000101101101111111
00000000000000000101101101111110
00000000000000000101101101111101
00000000000000000101101101111011
...
```

处理 2 位并没有太大的不同，尽管在可伸缩性方面更加激进（现在有 496 种可能的组合要输出，意味着 32 位中的任意 2 位组合）。

```scala
def twoBitsMasks: Set[Int] = {
  val masks = oneBitMasks
  masks flatMap { e1 =>
    masks.filter( e2 => e1 != e2) map { e2 =>
      e1 | e2
    }
  }
}

00000000000000000000000000000011
00000000000000000000000000000101
00000000000000000000000000000110
00000000000000000000000000001001
...
```

最后，我们构建我们的掩码集以应用（请注意，我们还希望通过应用 0 位差异掩码输出原始 Simhash）以检测重复，如下所示：

```scala
val searchmasks = twoBitsMasks ++ oneBitMasks ++ Set(0) 

```

这也帮助我们相应地扩展我们最初的 RDD。这肯定是一个昂贵的操作，因为它通过一个常数因子增加了我们的 RDD 的大小（496 + 32 + 1 种可能的组合），但在时间复杂度方面保持线性，而笛卡尔积连接是一个二次操作 - *O(n²).*

```scala
val duplicateTupleRDD = simhashRDD.flatMap {
  case ((id, _), simhash) =>
    searchmasks.map { mask =>
      (simhash ^ mask, id)
    }
}
.groupByKey()
```

我们发现文章 A 是文章 B 的副本，文章 B 是文章 C 的副本。这是一个简单的图问题，可以通过使用连接组件算法轻松解决*GraphX*。

```scala
val edgeRDD = duplicateTupleRDD
  .values
  .flatMap { it =>
    val list = it.toList
    for (x <- list; y <- list) yield (x, y)
  }
  .filter { case (x, y) =>
    x != y
  }
  .distinct()
  .map {case (x, y) =>
    Edge(x, y, 0)
  }

val duplicateRDD = Graph.fromEdges(edgeRDD, 0L)
  .connectedComponents()
  .vertices
  .join(simhashRDD.keys)
  .values
```

在用于该测试的 15,000 篇文章中，我们提取了大约 3,000 个不同的故事。我们在*图 7*中报告了一个例子，其中包括我们能够检测到的两篇近似重复的文章，它们都非常相似，但并非完全相同。

![在 GDELT 中检测近似重复](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_07_2.jpg)![在 GDELT 中检测近似重复](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_07_1-1.jpg)

图 7：GDELT 数据库中的 Galaxy Note 7 惨败

## 对 GDELT 数据库进行索引

下一步是开始构建我们的在线 API，以便任何用户都可以像 Facebook 在用户时间线上那样实时检测近似重复的事件。我们在这里使用*Play Framework*，但我们会简要描述，因为这已经在第八章*构建推荐系统*中涵盖过。

### 持久化我们的 RDD

首先，我们需要从我们的 RDD 中提取数据并将其持久化到可靠、可扩展且高效的位置以供按键搜索。由于该数据库的主要目的是在给定特定键（键为 Simhash）的情况下检索文章，**Cassandra**（如下所示的 maven 依赖）似乎是这项工作的不错选择。

```scala
<dependency>
  <groupId>com.datastax.spark</groupId>
  <artifactId>spark-cassandra-connector_2.11</artifactId>
</dependency>
```

我们的数据模型相当简单，由一个简单的表组成：

```scala
CREATE TABLE gzet.articles (
  simhash int PRIMARY KEY,
  url text,
  title text,
  body text
);
```

将我们的 RDD 存储到 Cassandra 的最简单方法是将我们的结果包装在一个与我们之前表定义匹配的案例类对象中，并调用`saveToCassandra`函数：

```scala
import com.datastax.spark.connector._

corpusRDD.map { case (content, simhash) =>
  Article(
    simhash,
    content.body,
    content.title,
    content.url
  )
}
.saveToCassandra(cassandraKeyspace, cassandraTable)
```

### 构建 REST API

下一步是着手处理 API 本身。我们创建一个新的 maven 模块（打包为`play2`）并导入以下依赖项：

```scala
<packaging>play2</packaging>

<dependencies>
  <dependency>
    <groupId>com.typesafe.play</groupId>
    <artifactId>play_2.11</artifactId>
  </dependency>
  <dependency>
    <groupId>com.datastax.cassandra</groupId>
    <artifactId>cassandra-driver-core</artifactId>
  </dependency>
</dependencies>
```

首先，我们创建一个新的**数据访问层**，它可以根据输入的 Simhash 构建我们之前讨论过的所有可能的 1 位和 2 位掩码的列表，并从 Cassandra 中提取所有匹配的记录：

```scala
class CassandraDao() {

  private val session = Cluster.builder()
                               .addContactPoint(cassandraHost)
                               .withPort(cassandraPort)
                               .build()
                               .connect()

  def findDuplicates(hash: Int): List[Article] = {
    searchmasks.map { mask =>
      val searchHash = mask ^ hash
      val stmt = s"SELECT simhash, url, title, body FROM gzet.articles WHERE simhash = $searchHash;"
      val results = session.execute(stmt).all()
      results.map { row =>
        Article(
           row.getInt("simhash"),
           row.getString("body"),
           row.getString("title"),
           row.getString("url")
        )
      }
      .head
    }
    .toList
  }
}
```

在我们的**控制器**中，给定一个输入 URL，我们提取 HTML 内容，对文本进行标记化，构建 Simhash 值，并调用我们的服务层，最终以 JSON 格式返回我们的匹配记录。

```scala
object Simhash extends Controller {

  val dao = new CassandraDao()
  val goose = new HtmlFetcher()

  def detect = Action { implicit request =>
    val url = request.getQueryString("url").getOrElse("NA")
    val article = goose.fetch(url)
    val hash = Tokenizer.lucene(article.body).simhash
    val related = dao.findDuplicates(hash)
    Ok(
        Json.toJson(
          Duplicate(
            hash,
            article.body,
            article.title,
            url,
            related
          )
       )
    )
  }
}
```

以下`play2`路由将重定向任何 GET 请求到我们之前看到的`detect`方法：

```scala
GET /simhash io.gzet.story.web.controllers.Simhash.detect 

```

最后，我们的 API 可以如下启动并向最终用户公开：

```scala
curl -XGET 'localhost:9000/simhash?url= http://www.detroitnews.com/story/tech/2016/10/12/samsung-damage/91948802/'

{
  "simhash": 1822083259,
  "body": "Seoul, South Korea - The fiasco of Samsung's [...]
  "title": "Fiasco leaves Samsung's smartphone brand [...]",
  "url": "http://www.detroitnews.com/story/tech/2016/[...]",
  "related": [
    {
      "hash": 1821919419,
      "body": "SEOUL, South Korea - The fiasco of [...]
      "title": "Note 7 fiasco leaves Samsung's [...]",
      "url": "http://www.chron.com/business/technology/[...]"
    },
    {
      "hash": -325433157,
      "body": "The fiasco of Samsung's fire-prone [...]
      "title": "Samsung's Smartphone Brand [...]",
      "url": "http://www.toptechnews.com/[...]"
    }
  ]
}
```

恭喜！您现在已经构建了一个在线 API，可以用于检测近似重复，比如 Galaxy Note 7 惨败周围的事件；但我们的 API 与 Facebook 的 API 相比有多准确？这肯定足够准确，可以开始通过将高度相似的事件分组成故事来去噪 GDELT 数据。

### 改进领域

尽管我们已经对 API 返回的结果总体质量感到满意，但在这里我们讨论了新闻文章的一个重大改进。事实上，文章不仅由不同的词袋组成，而且遵循一个清晰的结构，其中顺序确实很重要。事实上，标题总是一个噱头，主要内容仅在前几行内完全涵盖。文章的其余部分也很重要，但可能不像介绍那样重要。鉴于这一假设，我们可以稍微修改我们的 Simhash 算法，通过为每个单词分配不同的权重来考虑顺序。

```scala
implicit class Simhash(content: String) {

  // ../..

  def weightedSimhash = {

    val features = shingles(content)
    val totalWords = features.length
    val aggHashWeight = features.zipWithIndex
      .map {case (hash, id) =>
        (hash, 1.0 - id / totalWords.toDouble)
      }
      .flatMap { case (hash, weight) =>
        Range(0, 32).map { bit =>
          (bit, if(hash.isBitSet(bit)) weight else -weight)
        }
      }
      .groupBy(_._1)
      .mapValues(_.map(_._2).sum > 0)
      .toArray

    buildSimhash(0, aggHashWeight)
  }

}
```

与其在设置相同的位值时每次添加 1 或-1，不如根据单词在文章中的位置添加相应的权重。相似的文章将共享相同的单词、相同的词频，但也具有相似的结构。换句话说，在文本的前几行发生的任何差异，我们要比在每篇文章的最后一行发生的差异更不容忍。

# 构建故事

*Simhash*应该只用于检测近似重复的文章。将我们的搜索扩展到 3 位或 4 位的差异将变得非常低效（3 位差异需要 5,488 个不同的查询到 Cassandra，而需要 41,448 个查询来检测高达 4 位的差异），并且似乎会带来比相关文章更多的噪音。如果用户想要构建更大的故事，那么必须应用典型的聚类技术。

## 构建词频向量

我们将开始使用 KMeans 算法将事件分组成故事，以文章的词频作为输入向量。TF-IDF 简单、高效，是一种构建文本内容向量的成熟技术。基本思想是计算一个词频，然后使用数据集中的逆文档频率进行归一化，从而减少常见词（如停用词）的权重，同时增加特定于文档定义的词的权重。它的实现是 MapReduce 处理的基础之一，*Wordcount*算法。我们首先计算每个文档中每个单词的词频的 RDD。

```scala
val tfRDD = documentRDD.flatMap { case (docId, body) =>
  body.split("\\s").map { word =>
    ((docId, word), 1)
  }
}
.reduceByKey(_+_)
.map { case ((docId, word), tf) =>
  (docId, (word, tf))
}
```

IDF 是文档总数除以包含字母*w*的文档数的对数值：

![构建词频向量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_008.jpg)

```scala
val n = sc.broadcast(documentRDD.count())
val dfMap = sc.broadcast(
  tfRDD.map { case (docId, (word, _)) =>
    (docId, word)
  }
  .distinct()
  .values
  .map { word =>
    (word, 1)
  }
  .reduceByKey(_+_)
  .collectAsMap()
)

val tfIdfRDD = tfRDD.mapValues { case (word, tf) =>
  val df = dfMap.value.get(word).get
  val idf = math.log((n.value + 1) / (df + 1))
  (word, tf * idf)
}
```

由于我们的输出向量由单词组成，我们需要为语料库中的每个单词分配一个序列 ID。我们可能有两种解决方案。要么我们建立字典并为每个单词分配一个 ID，要么使用哈希函数将不同的单词分组到相同的桶中。前者是理想的，但会导致向量长度约为一百万个特征（与我们拥有的唯一单词数量一样多的特征），而后者要小得多（与用户指定的特征数量一样多），但可能会由于哈希碰撞而导致不良影响（特征越少，碰撞越多）。

```scala
val numFeatures = 256

val vectorRDD = tfIdfRDD.mapValues { case (word, tfIdf) =>
  val rawMod = word.hashCode % numFeatures
  rawMod + (if (rawMod < 0) numFeatures else 0)
  (word.hashCode / numFeatures, tfIdf)
}
.groupByKey()
.values
.map { it =>
  Vectors.sparse(numFeatures, it.toSeq)
}
```

尽管我们详细描述了 TF-IDF 技术，但这种散列 TF 只需要几行代码就可以完成，这要归功于 MLlib 实用程序，接下来我们将看到。我们构建了一个包含 256 个大向量的 RDD，（从技术上讲）可以用于 KMeans 聚类，但由于我们刚刚解释的哈希属性，我们将受到严重的哈希碰撞的影响。

```scala
val tfModel = new HashingTF(1 << 20)
val tfRDD = documentRDD.values.map { body =>
  tfModel.transform(body.split("\\s"))
}

val idfModel = new IDF().fit(tfRDD)
val tfIdfRDD = idfModel.transform(tfRDD)
val normalizer = new Normalizer()
val sparseVectorRDD = tfIdfRDD map normalizer.transform
```

## 维度诅咒，数据科学的灾难

将我们的特征大小从 256 增加到 2²⁰将大大限制碰撞的数量，但代价是我们的数据点现在嵌入在一个高度维度的空间中。

在这里，我们描述了一种聪明的方法来克服维度诅咒（[`www.stat.ucla.edu/~sabatti/statarray/textr/node5.html`](http://www.stat.ucla.edu/~sabatti/statarray/textr/node5.html)），而不必深入研究围绕矩阵计算的模糊数学理论（如奇异值分解），也不需要进行计算密集型的操作。这种方法被称为*随机索引*，类似于之前描述的*Simhash*概念。

### 注意

有关随机索引的更多信息可以在[`eprints.sics.se/221/1/RI_intro.pdf`](http://eprints.sics.se/221/1/RI_intro.pdf)找到。

这个想法是生成每个不同特征（这里是一个单词）的稀疏、随机生成和唯一表示，由+1、-1 和主要是 0 组成。然后，每当我们在一个上下文（一个文档）中遇到一个单词时，我们将这个单词的签名添加到上下文向量中。然后，文档向量是其每个单词向量的总和，如下的*图 8*（或我们的情况下每个 TF-IDF 向量的总和）所示：

![维度诅咒，数据科学的灾难](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_09.jpg)

图 8：构建随机索引向量

我们邀请我们纯粹的数学极客读者深入研究*Johnson-Lindenstrauss*引理（[`ttic.uchicago.edu/~gregory/courses/LargeScaleLearning/lectures/jl.pdf`](http://ttic.uchicago.edu/~gregory/courses/LargeScaleLearning/lectures/jl.pdf)），该引理基本上陈述了*"如果我们将向量空间中的点投影到足够高维度的随机选择的子空间中，点之间的距离将被近似保留"*。尽管*Random Indexing*技术本身可以实现（需要相当大的努力），*Johnson-Lindenstrauss*引理非常有用，但要理解起来要困难得多。幸运的是，*Derrick Burns*的优秀 spark-package *generalized-kmeans-clustering*（[`github.com/derrickburns/generalized-kmeans-clustering`](https://github.com/derrickburns/generalized-kmeans-clustering)）中包含了该实现。

```scala
val embedding = Embedding(Embedding.MEDIUM_DIMENSIONAL_RI)
val denseVectorRDD = sparseVectorRDD map embedding.embed
denseVectorRDD.cache()
```

我们最终能够将我们的 2²⁰大向量投影到*仅*256 维。这项技术至少提供了巨大的好处。

+   我们有固定数量的特征。如果将来遇到不在我们初始字典中的新单词，我们的向量大小将永远不会增长。这在流式上下文中将特别有用。

+   我们的输入特征集非常大（2²⁰）。尽管仍会发生碰撞，但风险已经减轻。

+   由于*Johnson-Lindenstrauss*引理，距离得以保留。

+   我们的输出向量相对较小（256）。我们克服了维度诅咒。

由于我们将向量 RDD 缓存在内存中，现在我们可以看看 KMeans 聚类本身。

## KMeans 的优化

我们假设我们的读者已经熟悉了 KMeans 聚类，因为这个算法可能是最著名和被广泛使用的无监督聚类算法。在这里再尝试解释将不如你能在超过半个世纪的积极研究后找到的许多资源那么好。

我们先前根据文章内容（TF-IDF）创建了我们的向量。下一步是根据它们的相似性将文章分组成故事。在 Spark 实现的 KMeans 中，只支持*欧氏距离*度量。有人会认为*余弦距离*更适合文本分析，但我们假设前者足够准确，因为我们不想重新打包 MLlib 分发以进行该练习。有关在文本分析中使用余弦距离的更多解释，请参阅[`www.cse.msu.edu/~pramanik/research/papers/2003Papers/sac04.pdf`](http://www.cse.msu.edu/~pramanik/research/papers/2003Papers/sac04.pdf)。我们在以下代码中报告了可以应用于任何双精度数组（密集向量背后的逻辑数据结构）的欧氏和余弦函数：

```scala
def euclidean(xs: Array[Double], ys: Array[Double]) = {
  require(xs.length == ys.length)
  math.sqrt((xs zip ys)
    .map { case (x, y) =>
      math.pow(y - x, 2)
    }
    .sum
  )
}

def cosine(xs: Array[Double], ys: Array[Double]) = {

  require(xs.length == ys.length)
  val magX = math.sqrt(xs.map(i => i * i).sum)
  val magY = math.sqrt(ys.map(i => i * i).sum)
  val dotP = (xs zip ys).map { case (x, y) =>
    x * y
  }.sum

  dotP / (magX * magY)
}
```

使用 MLlib 包训练新的 KMeans 聚类非常简单。我们指定一个阈值为 0.01，之后我们认为我们的聚类中心已经收敛，并将最大迭代次数设置为 1,000。

```scala
val model: KMeansModel = new KMeans()
  .setEpsilon(0.01)
  .setK(numberOfClusters)
  .setMaxIterations(1000)
  .run(denseVectorRDD)
```

但在我们特定的用例中，正确的聚类数是多少？在每 15 分钟批处理中有 500 到 1,000 篇不同的文章，我们可以构建多少个故事？正确的问题是，*我们认为在 15 分钟批处理窗口内发生了多少个真实事件？*实际上，为新闻文章优化 KMeans 与任何其他用例并无不同；这是通过优化其相关成本来实现的，成本是**点到它们各自质心的平方距离的总和**（**SSE**）。

```scala
val wsse = model.computeCost(denseVectorRDD) 

```

当*k*等于文章的数量时，相关成本为 0（每篇文章都是其自己聚类的中心）。同样，当*k*等于 1 时，成本将达到最大值。因此，*k*的最佳值是在添加新的聚类不会带来任何成本增益之后的最小可能值，通常在下图中显示的 SSE 曲线的拐点处表示。

使用迄今为止收集的所有 1.5 万篇文章，这里最佳的聚类数量并不明显，但可能大约在 300 左右。

![优化 KMeans](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_010.jpg)

图 9：使用成本函数的拐点法

一个经验法则是将*k*作为*n*（文章数量）的函数。有超过 1.5 万篇文章，遵循这个规则将返回*k* ![优化 KMeans](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_011.jpg) 100。

![优化 KMeans](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_012.jpg)

我们使用值为 100，并开始预测每个数据点的聚类。

```scala
val clusterTitleRDD = articleRDD
  .zip(denseVectorRDD)
  .map { case ((id, article), vector) =>
    (model.predict(vector), article.title)
  }
```

尽管这可能得到很大的改进，我们确认许多相似的文章被分在了同一个故事中。我们报告了一些属于同一聚类的与三星相关的文章：

+   *三星可以从泰诺、玩具和捷蓝学到什么...*

+   *华为 Mate 9 似乎是三星 Galaxy Note 7 的复制品...*

+   鉴于 Note 7 的惨败，三星可能会...*

+   *三星股价的螺旋式下跌吸引了投资者的赌注...*

+   *Note 7 惨败让三星智能手机品牌...*

+   *Note 7 惨败让三星智能手机品牌受到打击...*

+   *Note 7 惨败让三星智能手机品牌蒙上疑问的阴影...*

+   *Note 7 惨败让三星智能手机品牌蒙上疑问的阴影...*

+   *Note 7 惨败让三星智能手机品牌受到打击...*

+   *惨败让三星智能手机品牌蒙上疑问的阴影...*

可以肯定的是，这些相似的文章不符合 Simhash 查找的条件，因为它们的差异超过了 1 位或 2 位。聚类技术可以用来将相似（但不重复）的文章分成更广泛的故事。值得一提的是，优化 KMeans 是一项繁琐的任务，需要多次迭代和彻底分析。然而，在这里，这并不是范围的一部分，因为我们将专注于实时的更大的聚类和更小的数据集。

# 故事变异

现在我们有足够的材料来进入主题的核心。我们能够检测到近似重复的事件，并将相似的文章分组到一个故事中。在本节中，我们将实时工作（在 Spark Streaming 环境中），监听新闻文章，将它们分组成故事，同时也关注这些故事如何随时间变化。我们意识到故事的数量是不确定的，因为我们事先不知道未来几天可能出现什么事件。对于每个批次间隔（GDELT 中的 15 分钟），优化 KMeans 并不理想，也不高效，因此我们决定将这一约束条件不是作为限制因素，而是作为在检测突发新闻文章方面的优势。

## 平衡状态

如果我们将世界新闻文章分成 10 到 15 个类别，并固定该数量不会随时间改变，那么训练 KMeans 聚类应该能够将相似（但不一定是重复的）文章分成通用的故事。为方便起见，我们给出以下定义：

+   文章是在时间 T 涵盖特定事件的新闻文章。

+   故事是一组相似的文章，涵盖了一段时间 T 内的事件

+   主题是一组相似的故事，涵盖了一段时间内的不同事件 P

+   史诗是一组相似的故事，涵盖了一段时间内相同的事件 P

我们假设在一段时间内没有任何重大新闻事件之后，任何故事都将被分组到不同的*主题*中（每个主题涵盖一个或多个主题）。例如，任何关于政治的文章 - 无论政治事件的性质如何 - 都可以被分组到政治桶中。这就是我们所说的*平衡状态*，在这种状态下，世界被平均分成了 15 个不同而清晰的类别（战争、政治、金融、技术、教育等）。

但是，如果一个重大事件突然发生会发生什么呢？一个事件可能变得如此重要，以至于随着时间的推移（并且由于固定数量的集群），它可能会掩盖最不重要的*主题*并成为其自己的*主题*的一部分。类似于 BBC 广播限制在 30 分钟的时间窗口内，一些次要事件，比如*惠特斯特布尔的牡蛎节*，可能会被跳过，以支持一个重大的国际事件（令牡蛎的粉丝非常沮丧）。这个主题不再是通用的，而是现在与一个特定的事件相关联。我们称这个主题为一个*史诗*。例如，通用的*主题*[恐怖主义、战争和暴力]在去年 11 月成为了一个史诗[**巴黎袭击**]，当一个重大的恐怖袭击事件发生时，原本被认为是关于暴力和恐怖主义的广泛讨论变成了一个专门讨论巴黎事件的分支。

现在想象一个*史诗*不断增长；虽然关于**巴黎袭击**的第一篇文章是关于事实的，但几个小时后，整个世界都在向恐怖主义表示敬意和谴责。与此同时，法国和比利时警方进行了调查，追踪和解散恐怖主义网络。这两个故事都得到了大量报道，因此成为了同一个*史诗*的两个不同版本。这种分支的概念在下面的*图 10*中有所体现：

![平衡状态](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_013.jpg)

图 10：故事变异分支的概念

当然，有些史诗会比其他的持续时间更长，但当它们消失时 - 如果它们消失的话 - 它们的分支可能会被回收，以覆盖新的突发新闻（记住固定数量的集群），或者被重新用于将通用故事分组回到它们的通用主题。在某个时间点，我们最终达到了一个新的平衡状态，在这个状态下，世界再次完美地适应了 15 个不同的主题。我们假设，尽管如此，新的平衡状态可能不会是前一个的完美克隆，因为这种干扰可能已经在某种程度上雕刻和重新塑造了世界。作为一个具体的例子，我们现在仍然提到与 9/11 有关的文章；2001 年发生在纽约市的世界贸易中心袭击仍然对[暴力、战争和恐怖主义] *主题*的定义产生影响。

## 随着时间的推移跟踪故事

尽管前面的描述更多是概念性的，可能值得一篇关于应用于地缘政治的数据科学博士论文，但我们想进一步探讨这个想法，并看看流式 KMeans 如何成为这种用例的一个奇妙工具。

### 构建流应用

第一件事是实时获取我们的数据，因此修改我们现有的 NiFi 流以将我们下载的存档分叉到一个 Spark Streaming 上下文。一个简单的方法是**netcat**将文件的内容发送到一个打开的套接字，但我们希望这个过程是有弹性和容错的。NiFi 默认带有输出端口的概念，它提供了一个机制来使用*Site-To-Site*将数据传输到远程实例。在这种情况下，端口就像一个队列，希望在传输过程中不会丢失任何数据。我们通过在`nifi.properties`文件中分配一个端口号来启用这个功能。

```scala
nifi.remote.input.socket.port=8055 

```

我们在画布上创建了一个名为[`Send_To_Spark`]的端口，每条记录（因此`SplitText`处理器）都将被发送到它，就像我们在 Kafka 主题上所做的那样。

![构建流应用](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_014.jpg)

图 11：将 GKG 记录发送到 Spark Streaming

### 提示

尽管我们正在设计一个流应用程序，但建议始终在弹性数据存储（这里是 HDFS）中保留数据的不可变副本。在我们之前的 NiFi 流中，我们没有修改现有的流程，而是将其分叉，以便将记录发送到我们的 Spark Streaming。当/如果我们需要重放数据集的一部分时，这将特别有用。

在 Spark 端，我们需要构建一个 Nifi 接收器。这可以通过以下 maven 依赖项实现：

```scala
<dependency>
  <groupId>org.apache.nifi</groupId>
  <artifactId>nifi-spark-receiver</artifactId>
  <version>0.6.1</version>
</dependency>
```

我们定义 NiFi 端点以及我们之前分配的端口名称[`Send_To_Spark`]。我们的数据流将被接收为数据包流，可以使用`getContent`方法轻松转换为字符串。

```scala
def readFromNifi(ssc: StreamingContext): DStream[String] = {

  val nifiConf = new SiteToSiteClient.Builder()
    .url("http://localhost:8090/nifi")
    .portName("Send_To_Spark")
    .buildConfig()

  val receiver = new NiFiReceiver(nifiConf, StorageLevel.MEMORY_ONLY)
  ssc.receiverStream(receiver) map {packet =>
    new String(packet.getContent, StandardCharsets.UTF_8)
  }
}
```

我们启动我们的流上下文，并监听每 15 分钟到来的新 GDELT 数据。

```scala
val ssc = new StreamingContext(sc, Minutes(15)) 
val gdeltStream: DStream[String] = readFromNifi(ssc) 
val gkgStream = parseGkg(gdeltStream) 

```

下一步是为每篇文章下载 HTML 内容。这里的棘手部分是仅为不同的 URL 下载文章。由于`DStream`上没有内置的`distinct`操作，我们需要通过在其上使用`transform`操作并传递一个`extractUrlsFromRDD`函数来访问底层 RDD：

```scala
val extractUrlsFromRDD = (rdd: RDD[GkgEntity2]) => {
  rdd.map { gdelt =>
    gdelt.documentId.getOrElse("NA")
  }
  .distinct()
}
val urlStream = gkgStream.transform(extractUrlsFromRDD)
val contentStream = fetchHtml(urlStream)
```

同样，构建向量需要访问底层 RDD，因为我们需要计算整个批次的文档频率（用于 TF-IDF）。这也是在`transform`函数中完成的。

```scala
val buildVectors = (rdd: RDD[Content]) => {

  val corpusRDD = rdd.map(c => (c, Tokenizer.stem(c.body)))

  val tfModel = new HashingTF(1 << 20)
  val tfRDD = corpusRDD mapValues tfModel.transform

  val idfModel = new IDF() fit tfRDD.values
  val idfRDD = tfRDD mapValues idfModel.transform

  val normalizer = new Normalizer()
  val sparseRDD = idfRDD mapValues normalizer.transform

  val embedding = Embedding(Embedding.MEDIUM_DIMENSIONAL_RI)
  val denseRDD = sparseRDD mapValues embedding.embed

  denseRDD
}

val vectorStream = contentStream transform buildVectors
```

### 流式 K 均值

我们的用例完全适用于**流式 K 均值**算法。流式 K 均值的概念与经典的 K 均值没有区别，只是应用于动态数据，因此需要不断重新训练和更新。

在每个批处理中，我们找到每个新数据点的最近中心，对新的聚类中心进行平均，并更新我们的模型。随着我们跟踪真实的聚类并适应伪实时的变化，跟踪不同批次中相同的主题将特别容易。

流式 K 均值的第二个重要特征是遗忘性。这确保了在时间 t 接收到的新数据点将对我们的聚类定义产生更大的贡献，而不是过去历史中的任何其他点，因此允许我们的聚类中心随着时间平稳漂移（故事将变异）。这由衰减因子及其半衰期参数（以批次数或点数表示）控制，指定了给定点仅贡献其原始权重一半之后的时间。

+   使用无限衰减因子，所有历史记录都将被考虑在内，我们的聚类中心将缓慢漂移，并且如果有重大新闻事件突然发生，将不会做出反应

+   使用较小的衰减因子，我们的聚类将对任何点过于敏感，并且可能在观察到新事件时发生 drastical 变化

流式 K 均值的第三个最重要的特征是能够检测和回收垂死的聚类。当我们观察到输入数据发生 drastical 变化时，一个聚类可能会远离任何已知数据点。流式 K 均值将消除这个垂死的聚类，并将最大的聚类分成两个。这与我们的故事分支概念完全一致，其中多个故事可能共享一个共同的祖先。

我们在这里使用两个批次的半衰期参数。由于我们每 15 分钟获取新数据，任何新数据点只会保持*活跃*1 小时。训练流式 K 均值的过程如*图 12*所示：

![流式 K 均值](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_015.jpg)

图 12：训练流式 K 均值

我们创建一个新的流式 K 均值如下。因为我们还没有观察到任何数据点，所以我们用 256 个大向量（我们的 TF-IDF 向量的大小）的 15 个随机中心进行初始化，并使用`trainOn`方法实时训练它：

```scala
val model = new StreamingKMeans()
  .setK(15)
  .setRandomCenters(256, 0.0)
  .setHalfLife(2, "batches")

model.trainOn(vectorStream.map(_._2))
```

最后，我们对任何新数据点进行聚类预测：

```scala
val storyStream = model predictOnValues vectorStream  

```

然后，我们使用以下属性将我们的结果保存到我们的 Elasticsearch 集群中（通过一系列连接操作访问）。我们不在这里报告如何将 RDD 持久化到 Elasticsearch，因为我们认为这在之前的章节中已经深入讨论过了。请注意，我们还保存向量本身，因为我们可能以后会重新使用它。

```scala
Map(
  "uuid" -> gkg.gkgId,
  "topic" -> clusterId,
  "batch" -> batchId,
  "simhash" -> content.body.simhash, 
  "date" -> gkg.date,
  "url" -> content.url,
  "title" -> content.title,
  "body" -> content.body,
  "tone" -> gkg.tones.get.averageTone,
  "country" -> gkg.v2Locations,
  "theme" -> gkg.v2Themes,
  "person" -> gkg.v2Persons,
  "organization" -> gkg.v2Organizations,
  "vector" -> v.toArray.mkString(",")
)
```

### 可视化

由于我们将文章与它们各自的故事和*主题*存储在 Elasticsearch 中，我们可以使用关键词搜索（因为文章已经完全分析和索引）或特定的人物、主题、组织等来浏览任何事件。我们在我们的故事之上构建可视化，并尝试在 Kibana 仪表板上检测它们的潜在漂移。不同的集群 ID（我们的不同*主题*）随时间的变化在 11 月 13 日（索引了 35,000 篇文章）的*图 13*中报告：

![可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_016.jpg)

图 13：Kibana 巴黎袭击的可视化

结果相当令人鼓舞。我们能够在 11 月 13 日晚上 9:30 左右检测到**巴黎袭击**，距离第一次袭击开始只有几分钟。我们还确认了我们的聚类算法相对良好的一致性，因为一个特定的集群仅由与**巴黎袭击**相关的事件组成（5,000 篇文章），从晚上 9:30 到凌晨 3:00。

但我们可能会想知道在第一次袭击发生之前，这个特定的集群是关于什么的。由于我们将所有文章与它们的集群 ID 和它们的 GKG 属性一起索引，我们可以很容易地追踪一个故事在时间上的倒退，并检测它的变异。事实证明，这个特定的*主题*主要涵盖了与[MAN_MADE_DISASTER]主题相关的事件（等等），直到晚上 9 点到 10 点，当它转变为**巴黎袭击**的*史诗*，主题围绕着[TERROR]、[STATE_OF_EMERGENCY]、[TAX_ETHNICITY_FRENCH]、[KILL]和[EVACUATION]。

![可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_017.jpg)

图 14：Kibana 巴黎袭击集群的流图

不用说，我们从 GDELT 得到的 15 分钟平均语调在晚上 9 点后急剧下降，针对那个特定的*主题*：

![可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_018.jpg)

图 15：Kibana 平均语调-巴黎袭击集群

使用这三个简单的可视化，我们证明了我们可以随着时间追踪一个故事，并研究它在类型、关键词、人物或组织（基本上我们可以从 GDELT 中提取的任何实体）方面的潜在变异。但我们也可以查看 GKG 记录中的地理位置；有了足够的文章，我们可能可以在伪实时中追踪巴黎和布鲁塞尔之间的恐怖分子追捕活动！

尽管我们发现了一个特定于巴黎袭击的主要集群，并且这个特定的集群是第一个涵盖这一系列事件的集群，但这可能不是唯一的。根据之前的 Streaming KMeans 定义，这个*主题*变得如此庞大，以至于肯定触发了一个或多个随后的*史诗*。我们在下面的*图 16*中报告了与*图 13*相同的结果，但这次是过滤出与关键词*巴黎*匹配的任何文章：

![可视化](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_019.jpg)

图 16：Kibana 巴黎袭击的多个史诗

似乎在午夜左右，这个*史诗*产生了同一事件的多个版本（至少三个主要版本）。在袭击后一个小时（1 小时是我们的衰减因子）后，Streaming KMeans 开始回收垂死的集群，从而在最重要的事件（我们的*巴黎袭击*集群）中创建新的分支。

虽然主要的*史诗*仍然涵盖着事件本身（事实），但第二重要的是更多关于社交网络相关文章的。简单的词频分析告诉我们，这个*史诗*是关于**#portesOuvertes**（开放的大门）和**#prayForParis**标签，巴黎人以团结回应恐怖袭击。我们还发现另一个集群更关注所有向法国致敬并谴责恐怖主义的政治家。所有这些新故事都共享*巴黎袭击* *史诗*作为共同的祖先，但涵盖了不同的风味。

## 构建故事连接

我们如何将这些分支联系在一起？我们如何随着时间跟踪一个*史诗*，并查看它何时、是否、如何或为什么会分裂？当然，可视化有所帮助，但我们正在解决一个图问题。

因为我们的 KMeans 模型在每个批次中都在不断更新，我们的方法是检索我们使用过时版本模型预测的文章，从 Elasticsearch 中提取它们，并根据我们更新的 KMeans 模型进行预测。我们的假设如下：

*如果我们观察到在时间*t*时属于故事*s*的许多文章，现在在时间*![构建故事连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_22.jpg)*属于故事*s'*，*那么* **s** *很可能在* ![构建故事连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_23.jpg) *时间内迁移到* **s'**。*

作为一个具体的例子，第一个**#prayForParis**文章肯定属于*巴黎袭击* *史诗*。几个批次后，同一篇文章属于*巴黎袭击/社交网络*集群。因此，*巴黎袭击* *史诗*可能产生了*巴黎袭击/社交网络* *史诗*。这个过程在下面的*图 17*中有所报道：

![构建故事连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_10_020.jpg)

图 17：检测故事连接

我们从 Elasticsearch 中读取了一个 JSON RDD，并使用批处理 ID 应用了范围查询。在下面的例子中，我们想要访问过去一小时内构建的所有向量（最后四个批次），以及它们的原始集群 ID，并根据我们更新的模型重新预测它们（通过`latestModel`函数访问）：

```scala
import org.json4s.DefaultFormats
import org.json4s.native.JsonMethods._

val defaultVector = Array.fillDouble(0.0d).mkString(",")
val minBatchQuery = batchId - 4
val query = "{"query":{"range":{"batch":{"gte": " + minBatchQuery + ","lte": " + batchId + "}}}}"
val nodesDrift = sc.esJsonRDD(esArticles, query)
  .values
  .map { strJson =>
    implicit val format = DefaultFormats
    val json = parse(strJson)
    val vectorStr = (json \ "vector").extractOrElseString
    val vector = Vectors.dense(vectorStr.split(",").map(_.toDouble))
    val previousCluster = (json \ "topic").extractOrElseInt
    val newCluster = model.latestModel().predict(vector)
    ((previousCluster, newCluster), 1)
  }
  .reduceByKey(_ + _)
```

最后，一个简单的`reduceByKey`函数将计算过去一小时内不同边的数量。在大多数情况下，故事*s*中的文章将保持在故事*s*中，但在巴黎袭击的情况下，我们可能会观察到一些故事随着时间的推移向不同的*史诗*漂移。最重要的是，两个分支之间共享的连接越多，它们就越相似（因为它们的文章相互连接），因此它们在力导向布局中看起来越接近。同样，不共享许多连接的分支在相同的图形可视化中看起来会相距甚远。我们使用 Gephi 软件对我们的故事连接进行了力导向图表示，并在下面的*图 18*中报告。每个节点都是批次*b*上的一个故事，每条边都是我们在两个故事之间找到的连接数量。这 15 行是我们的 15 个*主题*，它们都共享一个共同的祖先（在首次启动流上下文时生成的初始集群）。

![构建故事连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_20.jpg)

图 18：故事变异的力导向布局

我们可以做出的第一个观察是这条线形状。这一观察令人惊讶地证实了我们对平衡状态的理论，即在巴黎袭击发生之前，大部分*主题*都是孤立的并且内部连接的（因此呈现这种线形状）。事件发生之前，大部分*主题*都是孤立的并且内部连接的（因此呈现这种线形状）。事件发生后，我们看到我们的主要*巴黎袭击* *史诗*变得密集、相互连接，并随着时间的推移而漂移。由于相互连接的数量不断增加，它似乎还拖着一些分支下降。这两个相似的分支是前面提到的另外两个集群（社交网络和致敬）。随着时间的推移，这个*史诗*变得越来越具体，自然地与其他故事有所不同，因此将所有这些不同的故事推向上方，形成这种散点形状。

我们还想知道这些不同分支是关于什么的，以及我们是否能解释为什么一个故事可能分裂成两个。为此，我们将每个故事的主要文章视为离其质心最近的点。

```scala
val latest = model.latestModel()
val topTitles = rdd.values
  .map { case ((content, v, cId), gkg) =>
    val dist = euclidean(
                  latest.clusterCenters(cId).toArray,
                  v.toArray
                  )
    (cId, (content.title, dist))
  }
  .groupByKey()
  .mapValues { it =>
    Try(it.toList.sortBy(_._2).map(_._1).head).toOption
  }
  .collectAsMap()
```

在*图 19*中，我们报告了相同的图表，并附上了故事标题。虽然很难找到一个清晰的模式，但我们找到了一个有趣的案例。一个*主题*涵盖了（其他事情之间的）与*哈里王子*开玩笑有关他的发型，稍微转移到*奥巴马*就巴黎袭击发表声明，最终变成了巴黎袭击和政客们支付的致敬。这个分支并非凭空出现，而似乎遵循了一个逻辑流程：

1.  [皇室，哈里王子，笑话]

1.  [皇室，哈里王子]

1.  [哈里王子，奥巴马]

1.  [哈里王子，奥巴马，政治]

1.  [奥巴马，政治]

1.  [奥巴马，政治，巴黎]

1.  [政治，巴黎]

![构建故事连接](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_10_21.jpg)

图 19：故事突变的力导向布局 - 标题

总之，似乎一条突发新闻事件作为平衡状态的突然扰动。现在我们可能会想知道这种扰动会持续多久，未来是否会达到新的平衡状态，以及由此产生的世界形状会是什么样子。最重要的是，不同的衰减因子对世界形状会产生什么影响。

如果有足够的时间和动力，我们可能会对应用物理学中的*摄动理论*（[`www.tcm.phy.cam.ac.uk/~bds10/aqp/handout_dep.pdf`](http://www.tcm.phy.cam.ac.uk/~bds10/aqp/handout_dep.pdf)）的一些概念感兴趣。我个人对在这个平衡点周围找到谐波很感兴趣。巴黎袭击事件之所以如此令人难忘，当然是因为其暴力性质，但也因为它发生在巴黎*查理周刊*袭击事件仅几个月后。

# 总结

这一章非常复杂，故事突变问题在允许交付本章的时间范围内无法轻易解决。然而，我们发现的东西真是令人惊奇，因为它引发了很多问题。我们并不想得出任何结论，所以我们在观察到巴黎袭击干扰后立即停止了我们的过程，并为我们的读者留下了这个讨论。请随意下载我们的代码库，并研究任何突发新闻及其在我们定义的平衡状态中的潜在影响。我们非常期待听到您的回音，并了解您的发现和不同的解释。

令人惊讶的是，在撰写本章之前，我们对*盖乐世 Note 7 惨败*一无所知，如果没有第一节中创建的 API，相关文章肯定会与大众无异。使用**Simhash**进行内容去重确实帮助我们更好地了解世界新闻事件。

在下一章中，我们将尝试检测与美国选举和新当选总统（*唐纳德·特朗普*）有关的异常推文。我们将涵盖*Word2Vec*算法和斯坦福 NLP 进行情感分析。
