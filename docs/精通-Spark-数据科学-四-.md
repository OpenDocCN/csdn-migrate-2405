# 精通 Spark 数据科学（四）

> 原文：[`zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25`](https://zh.annas-archive.org/md5/6A8ACC3697FE0BCDA4D2C7EE588C4E25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：情感分析中的异常检测

当我们回顾 2016 年时，我们肯定会记得这是一个许多重大地缘政治事件的时期，从英国脱欧，即英国决定退出欧盟的投票，到许多深受喜爱的名人的不幸去世，包括歌手大卫·鲍伊的突然去世（在第六章，*抓取基于链接的外部数据*和第七章，*构建社区*中有介绍）。然而，也许今年最显著的事件是紧张的美国总统选举及其最终结果，即唐纳德·特朗普当选总统。这将是一个长久被记住的竞选活动，尤其是因为它对社交媒体的前所未有的使用，以及在其用户中激起的激情，其中大多数人通过使用标签表达了他们的感受：要么是积极的，比如*#让美国再次伟大*或*#更强大*，要么是负面的，比如*#扔掉特朗普*或*#关起来*。由于本章是关于情感分析的，选举提供了理想的用例。但是，我们不打算试图预测结果本身，而是打算使用实时 Twitter 信息流来检测美国选举期间的异常推文。我们将涵盖以下主题：

+   实时和批量获取 Twitter 数据

+   使用斯坦福 NLP 提取情感

+   在*Timely*中存储情感时间序列

+   使用*Word2Vec*从仅 140 个字符中提取特征

+   介绍图*遍历性*和*最短路径*的概念

+   训练 KMeans 模型以检测潜在的异常

+   使用*TensorFlow*的*嵌入式投影仪*可视化模型

# 在 Twitter 上关注美国选举

2016 年 11 月 8 日，美国公民成千上万地前往投票站，为下一任美国总统投票。计票几乎立即开始，尽管直到稍后才正式确认，但预测的结果在第二天早上就已经众所周知。让我们从主要事件发生的几天前开始调查，即 2016 年 11 月 6 日，这样我们就可以在选举前保留一些背景信息。尽管我们事先不知道会发现什么，但我们知道*Twitter*将在政治评论中发挥超大作用，因为它在选举前的影响力很大，所以尽快开始收集数据是有意义的。事实上，数据科学家有时可能会有这种*直觉* - 一种奇怪而令人兴奋的想法，促使我们开始做某事，没有明确的计划或绝对的理由，只是觉得会有回报。实际上，这种方法可能至关重要，因为在制定和实现这样的计划所需的正常时间和事件的瞬息万变之间，可能会发生重大新闻事件（参见第十章，*故事去重和变异*），可能会发布新产品，或者股票市场可能会有不同的趋势（参见第十二章，*趋势演算*）；到那时，原始数据集可能已不再可用。

## 在流中获取数据

第一步是开始获取 Twitter 数据。由于我们计划下载超过 48 小时的推文，因此代码应该足够健壮，不会在过程中的某个地方失败；没有什么比在经过多小时的密集处理后发生致命的`NullPointerException`更令人沮丧的了。我们知道在未来某个时候我们将进行情感分析，但现在我们不希望用大型依赖项过度复杂化我们的代码，因为这可能会降低稳定性并导致更多未经检查的异常。相反，我们将开始收集和存储数据，随后的处理将在收集的数据上离线进行，而不是将此逻辑应用于实时流。

我们创建一个新的流上下文，使用第九章中创建的实用方法从 Twitter 1%的数据流中读取，新闻词典和实时标记系统。我们还使用优秀的 GSON 库将 Java 类`Status`（嵌入 Twitter4J 记录的 Java 类）序列化为 JSON 对象。

```scala
<dependency> 
  <groupId>com.google.code.gson</groupId>
  <artifactId>gson</artifactId>
  <version>2.3.1</version>
</dependency>
```

我们每 5 分钟读取一次 Twitter 数据，并可以选择作为命令行参数提供 Twitter 过滤器。过滤器可以是关键词，如***Trump***，***Clinton***或***#MAGA***，***#StrongerTogether***。然而，我们必须记住，通过这样做，我们可能无法捕获所有相关的推文，因为我们可能永远无法完全跟上最新的标签趋势（如***#DumpTrump***，***#DrainTheSwamp***，***#LockHerUp***或***#LoveTrumpsHate***），并且许多推文将被忽视，因为过滤器不足，因此我们将使用一个空的过滤器列表来确保我们捕捉到一切。

```scala
val sparkConf  = new SparkConf().setAppName("Twitter Extractor")
val sc = new SparkContext(sparkConf)
val ssc = new StreamingContext(sc, Minutes(5))

val filter = args

val twitterStream = createTwitterStream(ssc, filter)
  .mapPartitions { it =>
     val gson = new GsonBuilder().create()
     it.map { s: Status =>
       Try(gson.toJson(s)).toOption
     }
  }
```

我们使用 GSON 库对我们的`Status`类进行序列化，并将我们的 JSON 对象持久化在 HDFS 中。请注意，序列化发生在`Try`子句中，以确保不会抛出不需要的异常。相反，我们将 JSON 作为可选的`String`返回：

```scala
twitterStream
  .filter(_.isSuccess)
  .map(_.get)
  .saveAsTextFiles("/path/to/twitter")
```

最后，我们运行我们的 Spark 流上下文，并保持其活动状态，直到新总统当选，无论发生什么！

```scala
ssc.start()
ssc.awaitTermination()
```

## 批量获取数据

只有 1%的推文通过 Spark 流 API 检索，意味着 99%的记录将被丢弃。虽然能够下载大约 1000 万条推文，但这次我们可以潜在地下载更多的数据，但这次只针对选定的标签和在短时间内。例如，我们可以下载所有与***#LockHerUp***或***#BuildTheWall***标签相关的推文。

### 搜索 API

为此，我们通过`twitter4j` Java API 消耗 Twitter 历史数据。这个库作为`spark-streaming-twitter_2.11`的传递依赖项。要在 Spark 项目之外使用它，应该使用以下 maven 依赖项：

```scala
<dependency>
  <groupId>org.twitter4j</groupId>
  <artifactId>twitter4j-core</artifactId>
  <version>4.0.4</version>
</dependency>
```

我们创建一个 Twitter4J 客户端，如下所示：

```scala
ConfigurationBuilder builder = new ConfigurationBuilder();
builder.setOAuthConsumerKey(apiKey);
builder.setOAuthConsumerSecret(apiSecret);
Configuration configuration = builder.build();

AccessToken token = new AccessToken(
  accessToken,
  accessTokenSecret
);

Twitter twitter =
  new TwitterFactory(configuration)
      .getInstance(token);
```

然后，我们通过`Query`对象消耗`/search/tweets`服务：

```scala
Query q = new Query(filter);
q.setSince(fromDate);
q.setUntil(toDate);
q.setCount(400);

QueryResult r = twitter.search(q);
List<Status> tweets = r.getTweets();
```

最后，我们得到了一个`Status`对象的列表，可以很容易地使用之前介绍的 GSON 库进行序列化。

### 速率限制

Twitter 是数据科学的一个很棒的资源，但它远非一个非营利组织，因此他们知道如何评估和定价数据。在没有任何特殊协议的情况下，搜索 API 限制为几天的回顾，每 15 分钟窗口最多 180 次查询和每次查询最多 450 条记录。可以在 Twitter DEV 网站（[`dev.twitter.com/rest/public/rate-limits`](https://dev.twitter.com/rest/public/rate-limits)）和 API 本身使用`RateLimitStatus`类来确认这一限制：

```scala
Map<String, RateLimitStatus> rls = twitter.getRateLimitStatus("search");
System.out.println(rls.get("/search/tweets"));

/*
RateLimitStatusJSONImpl{remaining=179, limit=180, resetTimeInSeconds=1482102697, secondsUntilReset=873}
*/
```

毫不奇怪，任何关于热门词汇的查询，比如 2016 年 11 月 9 日的***#MAGA***，都会达到这个阈值。为了避免速率限制异常，我们必须通过跟踪处理的推文 ID 的最大数量，并在每次搜索请求后监视我们的状态限制来分页和限制我们的下载请求。

```scala
RateLimitStatus strl = rls.get("/search/tweets");
int totalTweets = 0;
long maxID = -1;
for (int i = 0; i < 400; i++) {

  // throttling
  if (strl.getRemaining() == 0)
    Thread.sleep(strl.getSecondsUntilReset() * 1000L);

  Query q = new Query(filter);
  q.setSince(fromDate);
  q.setUntil(toDate);
  q.setCount(100);

  // paging
  if (maxID != -1) q.setMaxId(maxID - 1);

  QueryResult r = twitter.search(q);
  for (Status s: r.getTweets()) {
    totalTweets++;
    if (maxID == -1 || s.getId() < maxID)
     maxID = s.getId();
     writer.println(gson.toJson(s));
  }
  strl = r.getRateLimitStatus();
}
```

每天大约有 50 亿条推文，如果收集所有与美国相关的数据，这将是乐观的，如果不是天真的。相反，应该使用前面详细介绍的简单摄取过程来拦截与特定查询匹配的推文。作为装配 jar 中的主类，可以按照以下方式执行：

```scala
java -Dtwitter.properties=twitter.properties /
  -jar trump-1.0.jar #maga 2016-11-08 2016-11-09 /
  /path/to/twitter-maga.json
```

在这里，`twitter.properties`文件包含您的 Twitter API 密钥：

```scala
twitter.token = XXXXXXXXXXXXXX
twitter.token.secret = XXXXXXXXXXXXXX
twitter.api.key = XXXXXXXXXXXXXX
twitter.api.secret = XXXXXXXXXXXXXX
```

# 分析情感

经过 4 天的密集处理，我们提取了大约 1000 万条推文；大约 30GB 的 JSON 数据。

## 整理 Twitter 数据

Twitter 变得如此受欢迎的一个关键原因是任何消息都必须适应最多 140 个字符。缺点也是每条消息都必须适应最多 140 个字符！因此，结果是缩写词、首字母缩略词、俚语、表情符号和标签的使用大幅增加。在这种情况下，主要情感可能不再来自文本本身，而是来自使用的表情符号（[`dl.acm.org/citation.cfm?id=1628969`](http://dl.acm.org/citation.cfm?id=1628969)），尽管一些研究表明表情符号有时可能导致情感预测不准确（[`arxiv.org/pdf/1511.02556.pdf`](https://arxiv.org/pdf/1511.02556.pdf)）。表情符号甚至比表情符号更广泛，因为它们包括动物、交通工具、商业图标等图片。此外，虽然表情符号可以通过简单的正则表达式轻松检索，但表情符号通常以 Unicode 编码，并且没有专用库更难提取。

```scala
<dependency>
  <groupId>com.kcthota</groupId>
  <artifactId>emoji4j</artifactId>
  <version>5.0</version>
</dependency>
```

`Emoji4J`库易于使用（尽管计算成本高昂），并且给定一些带有表情符号/表情符号的文本，我们可以`编码`- 用实际代码名称替换 Unicode 值 - 或`清理`- 简单地删除任何表情符号。

![整理 Twitter 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_01.jpg)

图 1：表情符号解析

因此，首先让我们清理文本中的任何垃圾（特殊字符、表情符号、重音符号、URL 等），以便访问纯英文内容：

```scala
import emoji4j.EmojiUtils

def clean = {
  var text = tweet.toLowerCase()
  text = text.replaceAll("https?:\\/\\/\\S+", "")
  text = StringUtils.stripAccents(text)
  EmojiUtils.removeAllEmojis(text)
    .trim
    .toLowerCase()
    .replaceAll("rt\\s+", "")
    .replaceAll("@[\\w\\d-_]+", "")
    .replaceAll("[^\\w#\\[\\]:'\\.!\\?,]+", " ")
    .replaceAll("\\s+([:'\\.!\\?,])\\1", "$1")
    .replaceAll("[\\s\\t]+", " ")
    .replaceAll("[\\r\\n]+", ". ")
    .replaceAll("(\\w)\\1{2,}", "$1$1") // avoid looooool 
    .replaceAll("#\\W", "")
    .replaceAll("[#':,;\\.]$", "")
    .trim
}
```

让我们也对所有表情符号和表情进行编码和提取，并将它们作为列表放在一边：

```scala
val eR = "(:\\w+:)".r

def emojis = {
  var text = tweet.toLowerCase()
  text = text.replaceAll("https?:\\/\\/\\S+", "")
  eR.findAllMatchIn(EmojiUtils.shortCodify(text))
    .map(_.group(1))
    .filter { emoji =>
      EmojiUtils.isEmoji(emoji)
    }.map(_.replaceAll("\\W", ""))
    .toArray
}
```

将这些方法写在*implicit class*中意味着它们可以通过简单的导入语句直接应用于字符串。

![整理 Twitter 数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_002.jpg)

图 2：Twitter 解析

## 使用斯坦福 NLP

我们的下一步是通过*情感注释器*传递我们清理过的文本。我们使用斯坦福 NLP 库来实现这一目的：

```scala
<dependency>
  <groupId>edu.stanford.nlp</groupId>
  <artifactId>stanford-corenlp</artifactId>
  <version>3.5.0</version>
  <classifier>models</classifier>
</dependency>

<dependency>
  <groupId>edu.stanford.nlp</groupId>
  <artifactId>stanford-corenlp</artifactId>
  <version>3.5.0</version>
</dependency>
```

我们创建一个斯坦福`注释器`，将内容标记为句子(`tokenize`)，分割句子(`ssplit`)，标记元素(`pos`)，并在分析整体情感之前对每个词进行词形还原(`lemma`)：

```scala
def getAnnotator: StanfordCoreNLP = {
  val p = new Properties()
  p.setProperty(
    "annotators",
    "tokenize, ssplit, pos, lemma, parse, sentiment"
  )
  new StanfordCoreNLP(pipelineProps)
}

def lemmatize(text: String,
              annotator: StanfordCoreNLP = getAnnotator) = {

  val annotation = annotator.process(text.clean)
  val sentences = annotation.get(classOf[SentencesAnnotation])
    sentences.flatMap { sentence =>
    sentence.get(classOf[TokensAnnotation])
  .map { token =>
    token.get(classOf[LemmaAnnotation])
  }
  .mkString(" ")
}

val text = "If you're bashing Trump and his voters and calling them a variety of hateful names, aren't you doing exactly what you accuse them?"

println(lemmatize(text))

/*
if you be bash trump and he voter and call they a variety of hateful name, be not you do exactly what you accuse they
*/
```

任何单词都被其最基本形式替换，即*you're*被替换为*you be*，*aren't you doing*被替换为*be not you do*。

```scala
def sentiment(coreMap: CoreMap) = {

 coreMap.get(classOf[SentimentCoreAnnotations.ClassName].match {
     case "Very negative" => 0
     case "Negative" => 1
     case "Neutral" => 2
     case "Positive" => 3
     case "Very positive" => 4
     case _ =>
       throw new IllegalArgumentException(
         s"Could not get sentiment for [${coreMap.toString}]"
       )
  }
}

def extractSentiment(text: String,
                     annotator: StanfordCoreNLP = getSentimentAnnotator) = {

  val annotation = annotator.process(text)
  val sentences = annotation.get(classOf[SentencesAnnotation])
  val totalScore = sentences map sentiment

  if (sentences.nonEmpty) {
    totalScore.sum / sentences.size()
  } else {
    2.0f
  }

}

extractSentiment("God bless America. Thank you Donald Trump!")
 // 2.5

extractSentiment("This is the most horrible day ever")
 // 1.0
```

情感范围从*非常消极*（0.0）到*非常积极*（4.0），并且每个句子的情感平均值。由于我们每条推文不会超过 1 或 2 个句子，我们预计方差非常小；大多数推文应该是*中性*（大约 2.0），只有极端情感会得分（低于~1.5 或高于~2.5）。

## 构建管道

对于我们的每条 Twitter 记录（存储为 JSON 对象），我们要做以下事情：

+   使用`json4s`库解析 JSON 对象

+   提取日期

+   提取文本

+   提取位置并将其映射到美国州

+   清理文本

+   提取表情符号

+   对文本进行词形还原

+   分析情感

然后，我们将所有这些值封装到以下`Tweet`案例类中：

```scala
case class Tweet(
            date: Long,
            body: String,
            sentiment: Float,
            state: Option[String],
            geoHash: Option[String],
            emojis: Array[String]
         )
```

如前几章所述，为我们数据集中的每条记录创建一个新的 NLP 实例并不可行。相反，我们每个`迭代器`（即每个分区）只创建一个`注释器`：

```scala
val analyzeJson = (it: Iterator[String]) => {

  implicit val format = DefaultFormats
  val annotator = getAnnotator
  val sdf = new SimpleDateFormat("MMM d, yyyy hh:mm:ss a")

  it.map { tweet =>

    val json = parse(tweet)
    val dateStr = (json \ "createdAt").extract[String]
    val date = Try(
      sdf.parse(dateStr).getTime
    )
     .getOrElse(0L)

    val text = (json \ "text").extract[String] 
    val location = Try(
      (json \ "user" \ "location").extract[String]
    )
     .getOrElse("")
     .toLowerCase()

     val state = Try {
       location.split("\\s")
        .map(_.toUpperCase())
        .filter { s =>
          states.contains(s)
        }
        .head
     }
     .toOption

    val cleaned = text.clean

    Tweet(
     date,
     cleaned.lemmatize(annotator),
     cleaned.sentiment(annotator),
     state, 
     text.emojis
    )
  }
}

val tweetJsonRDD = sc.textFile("/path/to/twitter")
val tweetRDD = twitterJsonRDD mapPartitions analyzeJson
tweetRDD.toDF().show(5)

/*
+-------------+---------------+---------+--------+----------+
|         date|           body|sentiment|   state|    emojis|
+-------------+---------------+---------+--------+----------+
|1478557859000|happy halloween|      2.0|    None [ghost]   |            
|1478557860000|slave to the gr|      2.5|    None|[]      |                 
|1478557862000|why be he so pe|      3.0|Some(MD)|[]        |
|1478557862000|marcador sentim|      2.0|    None|[]        |
|1478557868000|you mindset tow|      2.0|    None|[sparkles]|
+-------------+---------------+---------+--------+----------+
*/
```

# 使用 Timely 作为时间序列数据库

现在我们能够将原始信息转换为一系列干净的 Twitter 情感，其中包括标签、表情符号或美国州等参数，这样的时间序列应该能够可靠地存储，并且可以快速查询。

在 Hadoop 生态系统中，*OpenTSDB*（[`opentsdb.net/`](http://opentsdb.net/)）是存储数百万时间点数据的默认数据库。然而，我们将介绍一个您可能以前没有接触过的数据库，名为*Timely*（[`nationalsecurityagency.github.io/timely/`](https://nationalsecurityagency.github.io/timely/)）。Timely 是最近由**国家安全局**（**NSA**）开源的项目，作为 OpenTSDB 的克隆，它使用 Accumulo 而不是 HBase 作为其底层存储。正如您可能记得的那样，Accumulo 支持单元级安全，我们稍后将看到这一点。

## 存储数据

每条记录由一个指标名称（例如，标签），时间戳，指标值（例如，情感），一组相关标签（例如，州），以及一个单元可见性组成：

```scala
case class Metric(name: String,
                 time: Long,
                 value: Double,
                 tags: Map[String, String],
                 viz: Option[String] = None
                 )
```

在这个练习中，我们将筛选出只提到特朗普或克林顿的推文数据：

```scala
def expandedTweets = rdd.flatMap { tweet =>
  List("trump", "clinton") filter { f =>
    tweet.body.contains(f)
  } map { tag =>
    (tag, tweet)
  }
}
```

接下来，我们将构建一个名为`io.gzet.state.clinton`和`io.gzet.state.trump`的`Metric`对象，并附带一个可见性。在这个练习中，我们假设没有`SECRET`权限的初级分析师将不被授予访问高度负面的推文。这使我们能够展示 Accumulo 出色的单元级安全性：

```scala
def buildViz(tone: Float) = {
  if (tone <= 1.5f) Some("SECRET") else None: Option[String]
}
```

此外，我们还需要处理*重复记录*。如果在完全相同的时间收到多条推文（可能情感不同），它们将覆盖 Accumulo 上的现有单元：

```scala
def sentimentByState = {
  expandedTweets.map { case (tag, tweet) =>
    ((tag, tweet.date, tweet.state), tweet.sentiment)
  }
  .groupByKey()
  .mapValues { f =>
    f.sum / f.size
  }
  .map { case ((tag, date, state), sentiment) =>
    val viz = buildViz(sentiment)
    val meta = Map("state" -> state) 
    Metric("io.gzet.state.$tag", date, sentiment, meta, viz)
  }
}
```

我们可以通过`POST`请求插入数据，也可以通过打开的套接字将数据传送回 Timely 服务器：

```scala
def toPut = {

  val vizMap = if(viz.isDefined) {
    List("viz" -> viz.get)
  } else {
    List[(String, String)]()
  }

  val strTags = vizMap
    .union(tags.toList)
    .map { case (k, v) => s"$k=$v" }
    .mkString(" ")

  s"put $name $time $value $strTags"
}

implicit class Metrics(rdd: RDD[Metric]) {

  def publish = {

    rdd.foreachPartition { it: Iterator[Metric] =>

      val sock = new Socket(timelyHost, timelyPort)
      val writer = new PrintStream(
        sock.getOutputStream,
        true,
        StandardCharsets.UTF_8.name
      )

      it.foreach { metric =>
        writer.println(metric.toPut)
      }
      writer.flush()
    }

  }
}

tweetRDD.sentimentByState.publish
```

我们的数据现在安全地存储在 Accumulo 中，并且任何具有正确访问权限的人都可以使用。

我们已经创建了一系列的输入格式，以便将 Timely 数据检索回 Spark 作业中。这里不会涉及，但可以在我们的 GitHub 存储库中找到：

```scala
// Read  metrics from Timely
val conf = AccumuloConfig(
            "GZET",
            "alice",
            "alice",
            "localhost:2181"
            )

val metricsRDD = sc.timely(conf, Some("io.gzet.state.*"))
```

### 提示

在撰写本文时，Timely 仍在积极开发中，因此尚无法从 Spark/MapReduce 中使用干净的输入/输出格式。发送数据的唯一方式是通过 HTTP 或 Telnet。

## 使用 Grafana 来可视化情感

Timely 本身并不具备可视化工具。但是，它与*Grafana*（[`grafana.net/`](https://grafana.net/)）集成良好且安全，使用 timely-grafana 插件。更多信息可以在 Timely 网站上找到。

### 处理的推文数量

作为第一个简单的可视化，我们显示了 2016 年 11 月 8 日和 9 日（协调世界时）两位候选人的推文数量：

![处理的推文数量](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_03.jpg)

图 3：Timely 处理的推文

随着选举结果的公布，我们观察到与特朗普有关的推文越来越多。平均而言，我们观察到与克林顿相关的推文约为特朗普相关推文的 6 倍。

### 还我推特账号

情感的快速研究显示，情感相对较消极（平均为 1.3），两位候选人的推文没有显著差异，这不会帮助预测美国大选的结果。

![还我推特账号](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_04.jpg)

图 4：Timely 时间序列

然而，仔细观察后，我们发现了一个真正有趣的现象。2016 年 11 月 8 日，格林尼治标准时间下午 1 点左右（东部标准时间上午 8 点，也就是纽约第一个投票站开放的时间），我们观察到*情感方差*出现了大幅下降。在前面的图中可以看到这种奇怪的现象，这不能完全解释。我们可以推测，要么第一张正式投票标志着动荡的总统竞选活动的结束，并且是选举后回顾期的开始 - 也许是一个比以前更加基于事实的对话 - 或者特朗普的顾问们真的把他的 Twitter 账号收走是他们最伟大的主意。

现在我们举一个 Accumulo 安全性的多功能性的例子，通过以另一个用户登录 Grafana，这次没有授予`SECRET`授权。正如预期的那样，在接下来的图像中，情感看起来积极得多（因为极端负面情感被隐藏了），从而确认了 Timely 上的可见性设置；Accumulo 的优雅自然显而易见：

![还我推特账号](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_005.jpg)

图 5：非秘密的及时时间序列

如何创建 Accumulo 用户的示例可以在第七章*建立社区*中找到。

### 识别摇摆州

我们将从 Timely 和 Grafana 中利用的最后一个有趣特性是树状图聚合。由于所有美国州的名称都存储为度量属性的一部分，我们将为两位候选人创建一个简单的树状图。每个框的大小对应观察次数，颜色与观察到的情感相关：

![识别摇摆州](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_006.jpg)

图 6：及时-希拉里·克林顿的美国州树状图

当我们之前使用 2 天情感平均值时，我们无法区分共和党和民主党州，因为情感在统计上是平坦的，而且相对糟糕（平均为 1.3）。然而，如果我们只考虑选举前一天，那么它似乎更有趣，因为我们观察到情感数据中有更多的变化。在前面的图像中，我们看到佛罗里达州、北卡罗来纳州和宾夕法尼亚州-12 个摇摆州中的 3 个-对希拉里·克林顿的情感表现出意外的糟糕。这种模式是否可能是选举结果的早期指标？

# Twitter 和戈德温点

通过适当清理我们的文本内容，我们可以使用*Word2Vec*算法并尝试理解单词在其实际*上下文*中的含义。

## 学习上下文

正如它所说的，*Word2Vec*算法将一个单词转换为一个向量。其想法是相似的单词将嵌入到相似的向量空间中，并且因此在上下文中看起来彼此接近。

### 注意

有关`Word2Vec`算法的更多信息可以在[`papers.nips.cc/paper/5021-distributed-representations-of-words-and-phrases-and-their-compositionality.pdf`](https://papers.nips.cc/paper/5021-distributed-representations-of-words-and-phrases-and-their-compositionality.pdf)找到。

很好地集成到 Spark 中，可以通过以下方式训练*Word2Vec*模型：

```scala
import org.apache.spark.mllib.feature.Word2Vec

val corpusRDD = tweetRDD
   .map(_.body.split("\\s").toSeq)
   .filter(_.distinct.length >= 4)

val model = new Word2Vec().fit(corpusRDD)
```

在这里，我们将每条推文提取为一个单词序列，只保留至少有`4`个不同单词的记录。请注意，所有单词的列表需要适应内存，因为它被收集回驱动程序作为单词和向量的映射（作为浮点数组）。向量大小和学习率可以通过`setVectorSize`和`setLearningRate`方法进行调整。

接下来，我们使用 Zeppelin 笔记本与我们的模型进行交互，发送不同的单词并要求模型获取最接近的同义词。结果相当令人印象深刻：

```scala
model.findSynonyms("#lockherup", 10).foreach(println)

/*
(#hillaryforprison,2.3266071900089313)
(#neverhillary,2.2890002973310066)
(#draintheswamp,2.2440446323298175)
(#trumppencelandslide,2.2392471034643604)
(#womenfortrump,2.2331140131326874)
(#trumpwinsbecause,2.2182999853485454)
(#imwithhim,2.1950198833564563)
(#deplorable,2.1570936207197016)
(#trumpsarmy,2.155859656266577)
(#rednationrising,2.146132149205829)
*/  
```

虽然标签通常在标准 NLP 中被忽略，但它们对语气和情感有很大的贡献。标记为中性的推文实际上可能比听起来更糟，因为使用*#HillaryForPrison*或***#LockHerUp***等标签。因此，让我们尝试使用一个有趣的特征，称为*word-vector association*来考虑这一点。原始*Word2Vec*算法给出的这种关联的一个常见例子如下所示：

```scala
[KING] is at [MAN] what [QUEEN] is at [?????] 

```

这可以翻译为以下向量：

```scala
VKING - VQUEEN = VMAN - V???? 
V???? = VMAN - VKING + VQUEEN 

```

因此，最近的点应该是`[WOMEN]`。从技术上讲，这可以翻译如下：

```scala
import org.apache.spark.mllib.linalg.Vectors

def association(word1: String, word2: String, word3: String) = {

  val isTo = model
    .getVectors
    .get(word2)
    .get
    .zip(model.getVectors.get(word1).get)
    .map(t => t._1 - t._2)

 val what = model
   .getVectors
   .get(word3)
   .get

 val vec = isTo
   .zip(what)
   .map(t => t._1 + t._2)
   .map(_.toDouble)

 Vectors.dense(vec)

}

val assoc = association("trump", "republican", "clinton")

model.findSynonyms(assoc, 1)
     .foreach(println)

*// (democrat,1.6838367309269164)* 

```

保存/检索这个模型可以通过以下方式完成：

```scala
model.save(sc, "/path/to/word2vec")

val retrieved = Word2VecModel.load(sc, "/path/to/word2vec")
```

## 可视化我们的模型

由于我们的向量有 100 个维度，使用传统方法在图中表示它们很困难。但是，您可能已经了解到*Tensor Flow*项目及其最近开源的*Embedding Projector*（[`projector.tensorflow.org/`](http://projector.tensorflow.org/)）。由于其快速渲染高维数据的能力，该项目提供了一种很好的可视化我们模型的方式。它也很容易使用-我们只需将我们的向量导出为制表符分隔的数据点，加载到 Web 浏览器中，就可以了！

![可视化我们的模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_007.jpg)

图 7：嵌入项目，计算机的邻居

*嵌入投影仪*将高维向量投影到 3D 空间，其中每个维度代表前三个**主要成分**（**PCA**）之一。我们还可以构建自己的投影，基本上将我们的向量朝着四个特定方向拉伸。在下面的表示中，我们将我们的向量向左、向右、向上和向下拉伸到[`特朗普`]、[`克林顿`]、[`爱`]和[`恨`]：

![可视化我们的模型](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_08.jpg)

图 8：嵌入项目，自定义投影

现在我们有了一个大大简化的向量空间，我们可以更容易地理解每个单词以及它与邻居的关系（`民主党`与`共和党`，`爱`与`恨`）。例如，明年法国大选即将到来，我们看到法国与特朗普的距离比与克林顿的距离更近。这可能被视为即将到来的选举的早期指标吗？

## Word2Graph 和 Godwin 点

在您使用 Twitter 的*Word2Vec*模型很长时间之前，您可能已经遇到了敏感术语和对第二次世界大战的引用。事实上，这是迈克·戈德温在 1990 年最初提出的戈德温定律([`www.wired.com/1994/10/godwin-if-2/`](https://www.wired.com/1994/10/godwin-if-2/))，其规定如下：

> *随着在线讨论的延长，涉及纳粹或希特勒的比较的概率接近 1*

截至 2012 年，它甚至是牛津英语词典的一部分。

![Word2Graph 和 Godwin 点](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_009.jpg)

图 9：戈德温定律

### 构建 Word2Graph

尽管戈德温定律更多是修辞手法而不是实际的数学定律，但它仍然是一个引人入胜的异常现象，并且似乎与美国大选相关。自然地，我们决定使用图论进一步探索这个想法。第一步是将我们的模型广播回执行器并将我们的单词列表并行化。对于每个单词，我们输出前五个同义词，并构建一个带有单词相似度作为边权重的`Edge`对象。让我们来看一下：

```scala
val bModel = sc.broadcast(model)
val bDictionary = sc.broadcast(
  model.getVectors
    .keys
    .toList
    .zipWithIndex
    .map(l => (l._1, l._2.toLong + 1L))
    .toMap
)

import org.apache.spark.graphx._

val wordRDD = sc.parallelize(
  model.getVectors
    .keys
    .toSeq
    .filter(s => s.length > 3)
)

val word2EdgeRDD = wordRDD.mapPartitions { it =>
  val model = bModel.value
  val dictionary = bDictionary.value

  it.flatMap { from =>
    val synonyms = model.findSynonyms(from, 5)
    val tot = synonyms.map(_._2).sum
    synonyms.map { case (to, sim) =>
      val norm = sim / tot
      Edge(
           dictionary.get(from).get,
           dictionary.get(to).get,
           norm
         )
      }
   }
}

val word2Graph = Graph.fromEdges(word2EdgeRDD, 0L)

word2Graph.cache()
word2Graph.vertices.count()
```

为了证明戈德温定律，我们必须证明无论输入节点如何，我们都可以从该节点找到一条通往*Godwin 点*的路径。在数学术语中，这假设图是*遍历*的。由于我们有多个连接的组件，我们的图不能是遍历的，因为一些节点永远不会通向 Godwin 点。因此：

```scala
val cc = word2Graph
  .connectedComponents()
  .vertices
  .values
  .distinct
  .count

println(s"Do we still have faith in humanity? ${cc > 1L}")
// false
```

由于我们只有一个连接的组件，下一步是计算每个节点到 Godwin 点的最短路径：

```scala
import org.apache.spark.graphx.lib.ShortestPaths

val shortestPaths = ShortestPaths.run(graph, Seq(godwin))
```

最短路径算法非常简单，可以很容易地使用*Pregel*实现，使用第七章中描述的相同技术，*构建社区*。基本方法是在目标节点（我们的 Godwin 点）上启动 Pregel，并向其传入的边发送消息，每个跳跃增加一个计数器。每个节点将始终保持最小可能的计数器，并将此值向下游传播到其传入的边。当找不到更多的边时，算法停止。

我们使用 Godwin 深度为 16 来标准化这个距离，该深度是每个最短路径的最大值：

```scala
val depth = sc.broadcast(
  shortestPaths.vertices
    .values
    .filter(_.nonEmpty)
    .map(_.values.min)
    .max()
)

logInfo(s"Godwin depth is [${depth.value}]")
// 16

shortestPaths.vertices.map { case (vid, hops) =>
  if(hops.nonEmpty) {
    val godwin = Option(
      math.min(hops.values.min / depth.value.toDouble, 1.0)
    )
    (vid, godwin)
   } else {
     (vid, None: Option[Double])
   }
}
.filter(_._2.isDefined)
.map { case (vid, distance) =>
  (vid, distance.get)
}
.collectAsMap()
```

下图显示了深度为 4-我们将 0、1、2、3 和 4 的分数标准化为**0.0**、**0.25**、**0.5**、**0.75**和**1.0**：

![构建 Word2Graph](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_11_010.jpg)

图 10：标准化的 Godwin 距离

最后，我们收集每个顶点及其关联距离作为一个映射。我们可以很容易地将这个集合从最敏感的词到最不敏感的词进行排序，但我们不会在这里报告我们的发现（出于明显的原因！）。

在 2016 年 11 月 7 日和 8 日，这张地图包含了我们 Twitter 字典中的所有单词，意味着完全的遍历性。根据 Godwin 定律，任何单词，只要时间足够长，都可以导致 Godwin 点。在本章中，当我们从 Twitter 文本内容构建特征时，我们将稍后使用这张地图。

### 随机游走

通过*Word2Vec*算法模拟随机游走的一种方法是将图形视为一系列**马尔可夫链**。假设*N*个随机游走和转移矩阵*T*，我们计算转移矩阵*T^N*。给定一个状态*S[1]*（表示一个单词*w[1]*），我们提取从*S[1]*到*N*给定转移中的*S[N]*状态跳转的概率分布。实际上，给定一个约 100k 个单词的字典，这样一个转移矩阵的密集表示将需要大约 50GB 的内存。我们可以使用 MLlib 中的`IndexedRowMatrix`类轻松构建*T*的稀疏表示：

```scala
val size = sc.broadcast(
  word2Graph
    .vertices
    .count()
    .toInt
)

val indexedRowRDD = word2Graph.edges
  .map { case edge =>
    (edge.srcId,(edge.dstId.toInt, edge.attr))
  }
  .groupByKey()
  .map { case (id, it) =>
    new IndexedRow(id, Vectors.sparse(size.value, it.toSeq))
  }

val m1 = new IndexedRowMatrix(indexedRowRDD)
val m3 = m1.multiply(m2)
```

不幸的是，Spark 中没有内置的方法来执行支持稀疏矩阵的矩阵乘法。因此，矩阵 m2 需要是密集的，并且必须适合内存。一种解决方法是分解这个矩阵（使用 SVD）并利用 word2vec 矩阵的对称性质（如果单词*w[1]*是单词*w[2]*的同义词，那么*w[2]*是*w[1]*的同义词）来简化这个过程。使用简单的矩阵代数，可以证明给定一个矩阵*M*：

![随机游走](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_11.jpg)

和*M*对称，那么

![随机游走](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_12.jpg)

对于*n*的偶数和奇数值分别。理论上，我们只需要计算对角矩阵*S*的乘积。实际上，这需要大量的工作量，计算成本高，而且没有真正的价值（我们只是想生成随机词语关联）。相反，我们使用我们的 Word2Vec 图、Pregel API 和蒙特卡洛模拟生成随机游走。这将从种子`love`开始生成词语关联。算法在 100 次迭代后停止，或者当路径达到我们的 Godwin 点时停止。该算法的详细信息可以在我们的代码库中找到。

```scala
Godwin.randomWalks(graph, "love", 100) 

```

### 提示

还值得一提的是，如果存在一个整数*n*，使得 M^n> 0，则矩阵*M*被称为遍历的（因此也证明了 Godwin 定律）。

# 对讽刺检测的一小步

检测讽刺是一个活跃的研究领域（[`homes.cs.washington.edu/~nasmith/papers/bamman+smith.icwsm15.pdf`](http://homes.cs.washington.edu/~nasmith/papers/bamman+smith.icwsm15.pdf)）。事实上，对于人类来说，检测讽刺通常并不容易，那么对于计算机来说又怎么可能容易呢？如果我说“我们将让美国再次伟大”；在不了解我、观察我或听到我使用的语气的情况下，你怎么知道我是否真的是认真的？现在，如果你读到我发的一条推文，上面写着“我们将让美国再次伟大 :(:(:(”，这有帮助吗？

## 构建特征

我们相信仅凭英文文本是无法检测出讽刺的，尤其是当纯文本不超过 140 个字符时。然而，我们在本章中展示了表情符号在情感定义中可以起到重要作用。一个天真的假设是，一条既有积极情绪又有负面表情符号的推文可能会导致讽刺。除了语气，我们还发现一些词语与一些可以被分类为相当负面的想法/意识形态更接近。

### #爱战胜仇恨

我们已经证明了任何单词都可以在诸如[`clinton`]、[`trump`]、[`love`]和[`hate`]之类的单词之间的高维空间中表示。因此，对于我们的第一个提取器，我们使用这些单词之间的平均余弦相似度来构建特征：

```scala
case class Word2Score(
                     trump: Double,
                     clinton: Double,
                     love: Double,
                     hate: Double
                      )

def cosineSimilarity(x: Array[Float],
                    y: Array[Float]): Double = {

  val dot = x.zip(y).map(a => a._1 * a._2).sum
  val magX = math.sqrt(x.map(i => i*i).sum)
  val magY = math.sqrt(y.map(i => i*i).sum)

  dot / (magX * magY)
}

val trump = model.getVectors.get("trump").get
val clinton = model.getVectors.get("clinton").get
val love = model.getVectors.get("love").get
val hate = model.getVectors.get("hate").get

val word2Score = sc.broadcast(
   model.getVectors.map { case (word, vector) =>
     val scores = Word2Score(
                        cosineSimilarity(vector, trump),
                        cosineSimilarity(vector, clinton),
                        cosineSimilarity(vector, love),
                        cosineSimilarity(vector, hate)
                        )
     (word, scores)
   }
)
```

我们将这种方法公开为用户定义的函数，以便对每条推文可以根据这四个维度进行评分：

```scala
import org.apache.spark.sql.functions._
import collection.mutable.WrappedArray

val featureTrump = udf((words:WrappedArray[String]) => {
  words.map(word2Score.value.get)
       .map(_.get.trump)
       .sum / words.length
})

val featureClinton = udf((words:WrappedArray[String]) => {
  words.map(word2Score.value.get)
       .map(_.get.clinton)
       .sum / words.length
})

val featureLove = udf((words:WrappedArray[String]) => {
  words.map(word2Score.value.get)
       .map(_.get.love)
       .sum / words.length
})

val featureHate = udf((words:WrappedArray[String]) => {
  words.map(word2Score.value.get)
       .map(_.get.hate)
       .sum / words.length
})
```

### 评分表情符号

我们可以提取所有表情符号并运行基本的词频统计，以检索只使用最多的表情符号。然后我们可以将它们分类为五个不同的组：`爱`，`喜悦`，`笑话`，`悲伤`和`哭泣`：

```scala
val lov = sc.broadcast(
  Set("heart", "heart_eyes", "kissing_heart", "hearts", "kiss")
)

val joy = sc.broadcast(
  Set("joy", "grin", "laughing", "grinning", "smiley", "clap", "sparkles")
)

val jok = sc.broadcast(
  Set("wink", "stuck_out_tongue_winking_eye", "stuck_out_tongue")
)

val sad = sc.broadcast(
  Set("weary", "tired_face", "unamused", "frowning", "grimacing", "disappointed")
)

val cry = sc.broadcast(
  Set("sob", "rage", "cry", "scream", "fearful", "broken_heart")
)

val allEmojis = sc.broadcast(
  lov.value ++ joy.value ++ jok.value ++ sad.value ++ cry.value
)
```

再次，我们将此方法公开为可以应用于 DataFrame 的 UDF。表情符号得分为 1.0 将非常积极，而 0.0 将非常消极。

### 训练 KMeans 模型

设置了 UDF 后，我们获得了我们的初始 Twitter DataFrame 并构建了特征向量：

```scala
val buildVector = udf((sentiment: Double, tone: Double, trump: Double, clinton: Double, love: Double, hate: Double, godwin: Double) => {
  Vectors.dense(
    Array(
      sentiment,
      tone,
      trump,
      clinton,
      love,
      hate,
      godwin
    )
  )
})

val featureTweetDF = tweetRDD.toDF
  .withColumn("words", extractWords($"body"))
  .withColumn("tone", featureEmojis($"emojis"))
  .withColumn("trump", featureTrump($"body"))
  .withColumn("clinton", featureClinton($"body"))
  .withColumn("godwin", featureGodwin($"body"))
  .withColumn("love", featureLove($"words"))
  .withColumn("hate", featureHate($"words"))
  .withColumn("features",
    buildVector(
      $"sentiment",
      $"tone",
      $"trump",
      $"clinton",
      $"love",
      $"hate",
      $"godwin")
    )

import org.apache.spark.ml.feature.Normalizer

val normalizer = new Normalizer()
  .setInputCol("features")
  .setOutputCol("vector")
  .setP(1.0)
```

我们使用`Normalizer`类对向量进行归一化，并将 KMeans 算法的输入限制为只有五个簇。与第十章相比，*故事去重和变异*，这里 KMeans 优化（以*k*表示）并不重要，因为我们不感兴趣将推文分组到类别中，而是检测异常值（远离任何簇中心的推文）：

```scala
import org.apache.spark.ml.clustering.KMeans

val kmeansModel = new KMeans()
  .setFeaturesCol("vector")
  .setPredictionCol("cluster")
  .setK(5)
  .setMaxIter(Int.MaxValue)
  .setInitMode("k-means||")
  .setInitSteps(10)
  .setTol(0.01)
  .fit(vectorTweetDF)
```

我们建议使用 ML 包而不是 MLlib。在过去几个 Spark 版本中，这个包在数据集采用和催化剂优化方面有了巨大的改进。不幸的是，存在一个主要限制：所有 ML 类都被定义为私有的，不能被扩展。因为我们想要提取预测的簇旁边的距离，我们将不得不构建我们自己的欧几里得测量作为 UDF 函数：

```scala
import org.apache.spark.ml.clustering.KMeansModel

val centers = sc.broadcast(kmeansModel.clusterCenters)
import org.apache.spark.mllib.linalg.Vector

val euclidean = udf((v: Vector, cluster: Int) => {
   math.sqrt(centers.value(cluster).toArray.zip(v.toArray).map {
    case (x1, x2) => math.pow(x1 - x2, 2)
  }
  .sum)
})
```

最后，我们从我们的*特色推文* DataFrame 中预测我们的簇和欧几里得距离，并将此 DataFrame 注册为持久的 Hive 表：

```scala
val predictionDF = kmeansModel
   .transform(vectorTweetDF)
   .withColumn("distance", euclidean($"vector", $"cluster"))

predictionDF.write.saveAsTable("twitter")
```

## 检测异常

如果特征向量与任何已知簇中心的距离太远（以欧几里得距离表示），我们将认为推文是异常的。由于我们将预测存储为 Hive 表，我们可以通过简单的 SQL 语句对所有点进行排序，并只取前几条记录。

从我们的 Zeppelin 笔记本查询 Hive 时，报告了一个示例，如下所示：

![检测异常](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/B05261_11_13.jpg)

图 11：用于检测异常的 Zeppelin 笔记本

不详细介绍（异常推文可能会敏感），以下是从 Hive 查询中提取的一些示例：

+   今天祝你好运，美国 #投票 #我和她在一起 [鬼脸]

+   这太棒了，我们让美国再次变得伟大 [哭泣，尖叫]

+   我们爱你先生，谢谢你的不断爱 [哭泣]

+   我无法描述我现在有多么开心 #maga [哭泣，愤怒]

然而，请注意，我们发现的异常值并不都是讽刺性的推文。我们刚刚开始研究讽刺，需要进行大量的细化（包括手动工作），可能还需要更先进的模型（如*神经网络*）才能编写全面的检测器。

# 总结

本章的目的是涵盖关于时间序列、词嵌入、情感分析、图论和异常检测的不同主题。值得注意的是，用来说明示例的推文绝不反映作者自己的观点：“美国是否会再次变得伟大超出了本书的范围”：（：（-讽刺与否？

在下一章中，我们将介绍一种创新的方法，使用*TrendCalculus*方法从时间序列数据中检测趋势。这将用于市场数据，但可以轻松应用于不同的用例，包括我们在这里构建的*情感时间序列*。


# 第十二章：TrendCalculus

在数据科学家开始研究趋势成为一个热门话题之前，有一个更古老的概念，至今仍未得到很好的数据科学服务：趋势。目前，对趋势的分析，如果可以这样称呼的话，主要是由人们“用眼睛看”时间序列图表并提供解释。但人们的眼睛在做什么呢？

本章描述了在 Apache Spark 中实现的一种用于数值研究趋势的新算法，称为 TrendCalculus，由 Andrew Morgan 发明。原始的参考实现是用 Lua 语言编写的，并于 2015 年开源，代码可以在[`bitbucket.org/bytesumo/trendcalculus-public`](https://bitbucket.org/bytesumo/trendcalculus-public)上查看。

本章解释了核心方法，它可以快速提取时间序列上的趋势变化点；这些是趋势改变方向的时刻。我们将详细描述我们的 TrendCalculus 算法，并在 Apache Spark 中实现它。结果是一组可扩展的函数，可以快速比较时间序列上的趋势，以推断趋势并检查不同时间范围内的相关性。使用这些颠覆性的新方法，我们演示了如何构建因果排名技术，以从成千上万的时间序列输入中提取潜在的因果模型。

在本章中，我们将学习：

+   如何有效构建时间窗口摘要数据

+   如何有效地总结时间序列数据以减少噪音，以进行进一步的趋势研究

+   如何使用新的 TrendCalculus 算法从摘要数据中提取趋势反转*变化点*

+   如何创建在复杂*窗口*功能创建的分区上操作的**用户定义的聚合函数**（**UDAFs**），以及更常见的*group by*方法

+   如何从 UDAFs 返回多个值

+   如何使用滞后函数比较当前和先前的记录

当面临问题时，数据科学家首先考虑的假设之一与趋势有关；趋势是提供数据可视化的绝佳方式，特别适用于大型数据集，其中数据的一般变化方向通常是可见的。在第五章《用于地理分析的 Spark》中，我们制定了一个简单的算法来尝试预测原油价格。在那项研究中，我们集中于价格的变化方向，也就是价格的趋势。我们看到，趋势是一种自然的思考、解释和预测方式。

为了解释和演示我们的新趋势方法，本章分为两个部分。第一部分是技术性的，提供我们执行新算法所需的代码。第二部分是关于在真实数据上应用该方法。我们希望它能证明，趋势作为一个概念的表面简单性通常比我们最初想到的更复杂，特别是在存在噪音的情况下。噪音导致许多局部高点和低点（在本章中称为抖动），这可能使得确定趋势转折点和发现随时间变化的一般方向变得困难。忽略时间序列中的噪音，并提取可解释的趋势信号，提供了我们演示如何克服的核心挑战。

# 研究趋势

趋势的词典定义是某事物发展或变化的一般方向，但还有其他更专注的定义可能更有助于引导数据科学。其中两个定义来自研究社会趋势的 Salomé Areias 和欧盟官方统计机构 Eurostat：

*“趋势是指在较长时期内缓慢变化，通常是几年，通常与影响所测量现象的结构性原因有关。”* - 欧盟官方统计机构 EUROSTAT（[`ec.europa.eu/eurostat/statistics-explained/index.php/Glossary:Trend`](http://ec.europa.eu/eurostat/statistics-explained/index.php/Glossary:Trend)）

*“趋势是指行为或心态的转变，影响大量人群。”* - Salomé Areias，社会趋势评论员（[`salomeareias.wordpress.com/what-is-a-trend/`](https://salomeareias.wordpress.com/what-is-a-trend/)）

我们通常认为趋势不过是股市价格的长期上涨或下跌。然而，趋势也可以指与经济、政治、流行文化和社会相关的许多其他用例：例如，媒体报道新闻时揭示的情绪研究。在本章中，我们将以石油价格作为简单的演示；然而，该技术可以应用于任何趋势发生的数据：

+   **上升趋势**：当连续的峰值和低谷较高（高峰和低谷）时，称为向上或上升趋势。例如，以下图表中的第一个箭头是一系列峰值和低谷的结果，整体效果是增加。

+   **下降趋势**：当连续的峰值和低谷较低（低峰和低谷）时，称为向下或下降趋势。例如，以下图表中的第二个箭头是一系列峰值和低谷的结果，整体效果是下降。

+   **水平趋势**：这不是严格意义上的趋势，而是在任何方向上都没有明确定义的趋势。我们目前不特别关注这一点，但在本章后面会讨论。

![研究趋势](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_001.jpg)

### 注意

如果您搜索“higher highs”“higher lows”“trend”“lower highs”“lower lows”，您将看到超过 16,000 个结果，包括许多知名的金融网站。这是金融行业中趋势的标准做法和经验法则定义。

# TrendCalculus 算法

在本节中，我们将使用第五章“地理分析的 Spark”中看到的布伦特原油价格数据集作为示例用例，解释 TrendCalculus 实现的细节。

## 趋势窗口

为了衡量任何类型的变化，我们必须首先以某种方式对其进行量化。对于趋势，我们将以以下方式定义：

+   总体积极变化（通常表示为值增加）

Higher highs and higher lows => +1

+   总体消极变化（通常表示为值减少）

Lower highs and lower lows => -1

因此，我们必须将我们的数据转换为趋势方向的时间序列，即+1 或-1。通过将我们的数据分割成一系列窗口，大小为*n*，我们可以计算每个窗口的日期高点和低点：

![趋势窗口](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_002.jpg)

由于这种窗口化在数据科学中是一种常见的做法，因此合理地认为 Spark 中一定有一个实现；如果您阅读了第五章，“地理分析的 Spark”，您将会看到它们，以 Spark SQL 窗口函数的形式。让我们读取一些布伦特原油数据，这种情况下只是日期和当天原油收盘价（示例数据位于我们的代码库中）：

```scala
// Read in the data
val oilPriceDF = spark
   .read
   .option("header","true")
   .option("inferSchema", "true")
   .csv("brent_oil_prices.csv")
```

接下来，我们应该确保日期字段模式正确，以便我们可以在`window`函数中使用它。我们的示例数据集具有`dd/MM/yyyy`格式的`String`日期，因此我们将使用`java.text.SimpleDateFormat`将其转换为`yyyy-MM-dd`：

```scala
// A date conversion UDF
def convertDate(date:String) : String = {
     val dt = new SimpleDateFormat("dd/MM/yyyy").parse(date)
     val newDate = new SimpleDateFormat("yyyy-MM-dd").format(dt)
     newDate
}
```

这将使我们能够创建一个**用户定义函数**（**UDF**），我们可以用它来替换`oilPriceDF` DataFrame 中已有的日期列：

```scala
val convertDateUDF = udf {(Date: String) => convertDate(Date)}
val oilPriceDatedDF = oilPriceDF
    .withColumn("DATE", convertDate(oilPriceDF("DATE")))
```

作为一个快速的旁注，如果我们想要集中在数据的特定范围上，我们可以对其进行过滤：

```scala
val oilPriceDated2015DF = oilPriceDatedDF.filter("year(DATE)==2015")
```

现在我们可以使用 Spark 2.0 中引入的窗口函数来实现窗口：

```scala
val windowDF = oilPriceDatedDF.groupBy(
   window(oilPriceDatedDF.col("DATE"),"1 week", "1 week", "4 days"))
```

前述声明中的参数允许我们提供窗口大小、窗口偏移和数据偏移，因此这个模式实际上产生了一个带有数据开头偏移的滚动窗口。这样可以确保每个窗口都是构建的，以便始终包含星期一到星期五的数据（石油交易日），每个后续窗口都包含下一周的数据。

在这个阶段查看 DataFrame 以确保一切井然有序；我们不能像通常那样使用`show`方法，因为`windowDF`是一个`RelationalGroupedDataset`。因此，我们可以运行一个简单的内置函数来创建可读的输出。计算每个窗口的内容，显示前二十行并且不截断输出：

```scala
windowDF.count.show(20, false)
```

这将类似于这样：

```scala
+---------------------------------------------+-----+ 
|window                                       |count| 
+---------------------------------------------+-----+ 
|[2011-11-07 00:00:00.0,2011-11-14 00:00:00.0]|5    | 
|[2011-11-14 00:00:00.0,2011-11-21 00:00:00.0]|5    | 
|[2011-11-21 00:00:00.0,2011-11-28 00:00:00.0]|5    | 
+---------------------------------------------+-----+ 

```

这里，count 是窗口中的条目数，也就是我们的情况下的价格数。根据使用的数据，我们可能会发现一些窗口包含少于五个条目，因为数据缺失。我们将保留这些数据，否则输出中将会出现间断。

### 注意

在处理新数据集之前，绝对不能忽视数据质量，并且必须始终进行尽职调查，参见第四章*探索性数据分析*。

更改窗口大小*n*（在本例中为 1 周）将调整我们的调查规模。例如，大小为 1 周的*n*将提供每周的变化，而大小为 1 年的*n*将提供每年的变化（每个窗口的大小将为：[交易的周数*5]使用我们的数据）。当然，这完全取决于数据集的结构，即是否为每小时或每日价格等。在本章后面，我们将看到如何可以轻松地迭代地检查趋势，将数据的变化点作为第二次迭代的输入。

## 简单趋势

现在我们有了窗口化的数据，我们可以计算每个窗口的+1 或-1 值（简单趋势），因此我们需要制定一个趋势计算方程。我们可以通过前面图表中的示例进行可视化处理：

![简单趋势](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_003.jpg)

对于计算出的窗口集，我们可以将当前窗口与上一个窗口进行比较，从而显示更高的高点、更低的低点和更低的高点、更低的低点。

我们通过从每个窗口中选择以下内容来实现这一点：

+   最早的高价

+   最新的低价

利用这些信息，我们可以推导出我们的 TrendCalculus 方程：

![简单趋势](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_004.jpg)

其中：

+   **sign**：是函数（x > 0）？1：（（x < 0）？-1：0）

+   **H**：高

+   **L**：低

+   **Pi**：当前窗口

+   **Pi -1**：上一个窗口

例如，给定以下情景：

![简单趋势](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_005.jpg)

+   简单趋势 = sign(sign(HighDiff) + sign(LowDiff))

+   简单趋势 = sign(sign(1000-970) + sign(800-780))

+   简单趋势 = sign(sign(30) + sign(20))

+   简单趋势 = sign(1 + 1)

+   简单趋势 = sign(2)

+   简单趋势 = +1

也可能获得答案为 0。这将在本章后面详细解释，参见*边缘案例*。

## 用户定义的聚合函数

有许多方法可以以编程方式执行上述任务，我们将看看用于聚合数据的 UDF（Spark `UserDefinedAggregateFunction`），以便我们可以使用先前收集的窗口化数据。

我们希望能够像以前的 UDF 示例一样在窗口上使用函数。但是，标准 UDF 是不可能的，因为我们的窗口被表示为`RelationalGroupedDataset`。在运行时，这样一个集合的数据可能保存在多个 Spark 节点上，因此函数是并行执行的，而不是 UDF 的数据必须是共同定位的。因此，UDAF 对我们来说是一个好消息，因为这意味着我们可以在程序逻辑中实现并行化效率的关注点被抽象化，并且代码将自动扩展到大规模数据集！

总之，我们希望输出最早的高价及其日期，以及最新的低价及其日期（对于每个窗口），以便我们可以使用这些数据来计算之前描述的简单趋势。我们将编写一个扩展`UserDefinedAggregateFunction`的 Scala 类，其中包含以下函数：

+   `inputSchema`：提供给函数的输入数据的结构

+   `bufferSchema`：为此实例保存的内部信息（聚合缓冲区）的结构

+   `dataType`：输出数据结构的类型

+   `deterministic`：函数是否是`确定性`的（即，相同的输入总是返回相同的输出）

+   `initialize`：聚合缓冲区的初始状态；合并两个初始缓冲区必须始终返回相同的初始状态

+   `update`：使用输入数据更新聚合缓冲区

+   `merge`：合并两个聚合缓冲区

+   `evaluate`：根据聚合缓冲区计算最终结果

我们的类的完整代码如下所示，请参阅前面的定义，以便在阅读时了解每个的目的。代码故意留得相当冗长，以便更容易理解功能。实际上，我们肯定可以重构`update`和`merge`函数。

```scala
import java.text.SimpleDateFormat
import java.util.Date
import org.apache.spark.sql.Row
import org.apache.spark.sql.expressions.{MutableAggregationBuffer, UserDefinedAggregateFunction}
import org.apache.spark.sql.types._

class HighLowCalc extends UserDefinedAggregateFunction {

// we will input (date, price) tuples
def inputSchema: org.apache.spark.sql.types.StructType = StructType(
  StructField("date", StringType) ::
  StructField("price", DoubleType) :: Nil)

// these are the values we will keep a track of internally
def bufferSchema: StructType = StructType(
  StructField("HighestHighDate", StringType) ::
  StructField("HighestHighPrice", DoubleType) ::
  StructField("LowestLowDate", StringType) ::
  StructField("LowestLowPrice", DoubleType) :: Nil
)

// the schema of our final output data
def dataType: DataType = DataTypes.createStructType(
  Array(
    StructField("HighestHighDate", StringType),
    StructField("HighestHighPrice", DoubleType),
    StructField("LowestLowDate", StringType),
    StructField("LowestLowPrice", DoubleType)
  )
)

// this function is deterministic
def deterministic: Boolean = true

// define our initial state using the bufferSchema
def initialize(buffer: MutableAggregationBuffer): Unit = {
  // the date of the highest price so far
  buffer(0) = ""
  // the highest price seen so far
  buffer(1) = 0d
  // the date of the lowest price so far
  buffer(2) = ""
  // the lowest price seen so far
  buffer(3) = 1000000d
}

// how to behave given new input (date, price)
def update(buffer: MutableAggregationBuffer,input: Row): Unit = {

  // find out how the input price compares
  // to the current internal value - looking for highest price only
  (input.getDouble(1) compare buffer.getAsDouble).signum match {
    // if the input price is lower then do nothing
    case -1 => {}
    // if the input price is higher then update the internal status
    case  1 => {
      buffer(1) = input.getDouble(1)
      buffer(0) = input.getString(0)
    }
    // if the input price is the same then ensure we have the earliest date
    case  0 => {
      // if new date earlier than current date, replace
      (parseDate(input.getString(0)),parseDate(buffer.getAsString))
      match {
        case (Some(a), Some(b)) => {
          if(a.before(b)){
            buffer(0) = input.getString(0)
          }
        }
        // anything else do nothing
        case _ => {}
      }
    }
  }
  // now repeat to find the lowest price
  (input.getDouble(1) compare buffer.getAsDouble).signum match {
    // if the input price is lower then update the internal state
    case -1 => {
      buffer(3) = input.getDouble(1)
      buffer(2) = input.getString(0)
    }
    // if the input price is higher then do nothing
    case  1 => {}
    // if the input price is the same then ensure we have the latest date
    case  0 => {
      // if new date later than current date, replace
      (parseDate(input.getString(0)),parseDate(buffer.getAsString))
      match {
        case (Some(a), Some(b)) => {
          if(a.after(b)){
            buffer(2) = input.getString(0)
          }
        }
        // anything else do nothing
        case _ => {}
      }
    }
  }
}

// define the behaviour to merge two aggregation buffers together
def merge(buffer1: MutableAggregationBuffer, buffer2: Row): Unit = {
  // first deal with the high prices
  (buffer2.getDouble(1) compare buffer1.getAsDouble).signum match {
    case -1 => {}
    case  1 => {
      buffer1(1) = buffer2.getDouble(1)
      buffer1(0) = buffer2.getString(0)
    }
    case  0 => {
      // work out which date is earlier
      (parseDate(buffer2.getString(0)),parseDate(buffer1.getAsString))
      match {
        case (Some(a), Some(b)) => {
          if(a.before(b)){
            buffer1(0) = buffer2.getString(0)
          }
        }
        case _ => {}
      }
    }
  }
  // now deal with the low prices
  (buffer2.getDouble(3) compare buffer1.getAsDouble).signum match {
    case -1 => {
      buffer1(3) = buffer2.getDouble(3)
      buffer1(2) = buffer2.getString(2)
    }
    case  1 => {}
    case  0 => {
      // work out which date is later
      (parseDate(buffer2.getString(2)),parseDate(buffer1.getAsString))
      match {
        case (Some(a), Some(b)) => {
          if(a.after(b)){
            buffer1(2) = buffer2.getString(2)
          }
        }
        case _ => {}
      }
    }
  }
}

// when all is complete, output:
// (highestDate, highestPrice, lowestDate, lowestPrice)
def evaluate(buffer: Row): Any = {
  (buffer(0), buffer(1), buffer(2), buffer(3))
}

// convert a String to a Date for easy comparison
def parseDate(value: String): Option[Date] = {
  try {
    Some(new SimpleDateFormat("yyyy-MM-dd").parse(value))
  } catch {
    case e: Exception => None
  }
}

}
```

您会注意到`signum`函数的常见用法。这对于比较非常有用，因为它产生以下结果：

+   如果第一个值小于第二个值，则输出-1

+   如果第一个值大于第二个值，则输出+1

+   如果两个值相等，则输出 0

当我们编写代码来计算实际的简单趋势值时，这个函数将在本章后面真正显示其价值。我们还使用了`option`类（在`parseDate`中），它使我们能够返回`Some`或`None`的实例。这有许多优点：主要是通过消除立即检查空值来促进关注点的分离，还可以使用模式匹配，允许我们链式连接许多 Scala 函数，而无需冗长的类型检查。例如，如果我们编写一个返回`Some(Int)`或`None`的函数，那么我们可以`flatMap`这些值而无需额外的检查：

```scala
List("1", "2", "a", "b", "3", "c").flatMap(a =>
   try {
      Some(Integer.parseInt(a.trim))
   } catch {
      case e: NumberFormatException => None
   }
}).sum
```

上述代码返回`Int = 6`。

## 简单趋势计算

现在我们有了聚合函数，我们可以注册它并使用它来输出值到我们的 DataFrame：

```scala
val hlc = new HighLowCalc
spark.udf.register("hlc", hlc)

val highLowDF = windowDF.agg(expr("hlc(DATE,PRICE) as highLow"))
highLowDF.show(20, false)
```

生成类似于以下内容的输出：

```scala
+-----------------------------+----------------------+
|window                       |highLow               |        
|                             |                      |
+-----------------------------+----------------------+
|[2011-11-07 00:00:00.0,… ]   |[2011-11-08,115.61,… ]|
|[2011-11-14 00:00:00.0,… ]   |[2011-11-14,112.57,… ]|
|[2011-11-21 00:00:00.0,… ]   |[2011-11-22,107.77,… ]|
```

我们已经提到，我们需要将当前窗口与上一个窗口进行比较。我们可以通过实现 Spark 的`lag`函数创建一个包含上一个窗口详情的新 DataFrame：

```scala
// ensure our data is in correct date order by sorting
// on each first date in the window column window
// Struct contains the values start and end
val sortedWindow = Window.orderBy("window.start")

// define the lag of just one row
val lagCol = lag(col("highLow"), 1).over(sortedWindow)

// create a new DataFrame with the additional column "highLowPrev"
// where the previous row does not exist, null will be entered
val highLowPrevDF = highLowDF.withColumn("highLowPrev", lagCol)
```

现在我们有了一个 DataFrame，其中每一行都包含计算简单趋势值所需的所有信息。我们可以再次实现一个 UDF，这次使用先前提到的`signum`函数来表示简单趋势方程：

```scala
val simpleTrendFunc = udf {
  (currentHigh : Double, currentLow : Double,
   prevHigh : Double, prevLow : Double) => {
     (((currentHigh - prevHigh) compare 0).signum +
     ((currentLow - prevLow) compare 0).signum compare 0).signum }
}
```

最后，将 UDF 应用于我们的 DataFrame：

```scala
val simpleTrendDF = highLowPrevDF.withColumn("sign",   
    simpleTrendFunc(highLowPrevDF("highLow.HighestHighPrice"),
     highLowPrevDF("highLow.LowestLowPrice"),
     highLowPrevDF("highLowPrev.HighestHighPrice"),
     highLowPrevDF("highLowPrev.LowestLowPrice")
    )
)

// view the DataFrame
simpleTrendDF.show(20, false)

+----------------------+----------------------+-----+
|highLow               |highLowPrev           |sign |
+----------------------+----------------------+-----+
|2011-11-08,115.61,...|null                  |null |
|[2011-11-14,112.57,...|2011-11-08,115.61,... |-1   |
|[2011-11-22,107.77,...|[2011-11-14,112.57,...|1    |
```

## 反转规则

在所有识别的窗口上运行代码后，我们现在的数据表示为一系列+1 和-1，并且我们可以进一步分析这些数据以进一步了解趋势。您会注意到数据看起来是随机的，但我们可以识别出一个模式：趋势值经常翻转，要么从+1 到-1，要么从-1 到+1。在更仔细地检查这些点的图表时，我们可以看到这些翻转实际上代表了趋势的反转：

![反转规则

这可以总结如下：

+   如果趋势从+1 移动到-1，则先前的高点是一个反转

+   如果趋势从-1 移动到+1，则先前的低点是一个反转

使用这个简单的规则，我们可以输出一个新的时间序列，其中包含我们在比例上找到的反转点。在这个时间序列中，我们将创建元组（日期，价格），这些元组等同于+1 反转的更高高点和-1 反转的更低低点，如前面讨论的那样。我们可以通过使用与之前相同的方法来编写代码，即使用`lag`函数捕获先前的符号，并实现 UDF 来计算反转，如下所示：

```scala
// define the lag of just one row
val lagSignCol = lag(col("sign"), 1).over(sortedWindow)

// create a new DataFrame with the additional column signPrev
val lagSignColDF = simpleTrendDF.withColumn("signPrev", lagSignCol)

// define a UDF that calculates the reversals
val reversalFunc = udf {
  (currentSign : Int, prevSign : Int,
    prevHighPrice : Double, prevHighDate : String,
    prevLowPrice : Double, prevLowDate : String) => {
      (currentSign compare prevSign).signum match {
        case 0 => null
        // if the current SimpleTrend is less than the
        // previous, the previous high is a reversal
        case -1 => (prevHighDate, prevHighPrice)
        // if the current SimpleTrend is more than the
        // previous, the previous low is a reversal
        case 1 => (prevLowDate, prevLowPrice)
      }
    }
}

// use the UDF to create a new DataFrame with the
// additional column reversals
val reversalsDF = lagSignColDF.withColumn("reversals",
  reversalFunc(lagSignColDF("sign"),
    lagSignColDF("signPrev"),
    lagSignColDF("highLowPrev.HighestHighPrice"),
    lagSignColDF("highLowPrev.HighestHighDate"),
    lagSignColDF("highLowPrev.LowestLowPrice"),
    lagSignColDF("highLowPrev.LowestLowDate")
  )
)

reversalsDF.show(20, false)

+----------------------+------+--------+--------------------+
|highLowPrev           |sign  |signPrev|reversals           |
+----------------------+------+-----------------------------+
|null                  |null  |null    |null                |
|[2011-11-08,115.61,… ]|-1    |null    |null                |
|[2011-11-14,112.57,… ]|-1    |-1      |null                |
|[2011-11-22,107.77,… ]|1     |-1      |[2011-11-24,105.3]  |
|[2011-11-29,111.25,… ]|-1    |1       |[2011-11-29,111.25] |
```

总之，我们成功地从我们的价格数据中去除了抖动（非显著的上升和下降），并且我们可以从中受益，立即显示这些数据。它肯定会显示原始数据集的简化表示，并且假设我们主要关注价格显著变化的点，它保留了与重要峰值和谷值相关的关键信息。然而，我们可以做更多的工作来以一种可呈现和易于阅读的方式表示数据。

## 引入 FHLS 条形结构

在金融领域，**开盘价、最高价、最低价、收盘价**（**OHLC**）图表非常常见，因为它们显示了每个分析师所需的关键数据；物品的开盘价和收盘价，以及该时期的最高价和最低价（通常为一天）。我们可以利用这个想法来达到我们自己的目的。**第一、最高、最低、第二**（**FHLS**）图表将使我们能够可视化我们的数据并在此基础上产生新的见解。

FHLS 数据格式描述如下：

+   开放日期

+   首先是高/低值 - 无论是高点还是低点先出现

+   高值

+   低值

+   第二个高/低值 - 高/低值中的另一个值先出现

+   高日期

+   低日期

+   关闭日期

我们几乎已经在先前描述的`reversalsDF`中获得了所有需要的数据，我们尚未确定的只有第一和第二值，也就是在任何给定窗口中最高或最低价格是先出现的。我们可以使用 UDF 或选择语句来计算这一点，但是更新之前的`UserDefinedAggregateFunction`将使我们能够进行小的更改，同时确保方法的高效性。只有评估函数需要更改：

```scala
def evaluate(buffer: Row): Any = {
  // compare the highest and lowest dates
  (parseDate(buffer.getString(0)), parseDate(buffer.getString(2))) match {
     case (Some(a), Some(b)) => {
       // if the highest date is the earlier
       if(a.before(b)){
         // highest date, highest price, lowest date,
         // lowest price, first(highest price), second
         (buffer(0), buffer(1), buffer(2), buffer(3), buffer(1), buffer(3))
       }
       else {
         // the lowest date is earlier or they are
         // both the same (shouldn’t be possible)
         // highest date, highest price, lowest date,
         // lowest price, first(lowest price), second
         (buffer(0), buffer(1), buffer(2), buffer(3), buffer(3), buffer(1))
       }
     }
     // we couldn’t parse one or both of the dates -shouldn’t reach here
     case _ =>
       (buffer(0), buffer(1), buffer(2), buffer(3), buffer(1), buffer(3))
  }
}
```

最后，我们可以编写一个语句来选择所需的字段并将我们的数据写入文件：

```scala
val fhlsSelectDF = reversalsDF.select(
 "window.start",
 "highLow.firstPrice",
 "highLow.HighestHighPrice",
 "highLow.LowestLowPrice",
 "highLow.secondPrice",
 "highLow.HighestHighDate",
 "highLow.LowestLowDate",
 "window.end",
 "reversals._1",
 "reversals._2")
```

您会注意到反转列不像其他列一样实现了`Struct`，而是一个元组。如果您检查`reversalsUDF`，您将看到是如何做到的。为了演示目的，我们将展示如何在选择后重命名组件字段：

```scala
val lookup = Map("_1" -> "reversalDate", "_2" -> "reversalPrice")
val fhlsDF = fhlsSelectDF.select { fhlsSelectDF.columns.map(c =>
   col(c).as(lookup.getOrElse(c, c))):_*
}
fhlsDF.orderBy(asc("start")).show(20, false)
```

将数据写入文件：

```scala
   fhlsDF.write
     .format("com.databricks.spark.csv")
     .option("header", "true")
     .save("fhls");
```

您可以通过添加以下行对数据进行加密：

```scala
.option("codec", "org.apache.hadoop.io.compress.CryptoCodec")
```

这个重要的编解码器和其他安全相关技术在第十三章 *安全数据*中有描述。

## 可视化数据

现在我们已经有了文件中的数据，我们可以利用这个机会来展示它；有许多可用于创建图表的软件包，作为一名数据科学家，其中一个关键的软件包就是 D3.js。正如我们在本书的其他部分提到的 D3 一样，我们的目的不是在这里探索比必要的更多的细节，而是产生我们最终结果所需的。也就是说，值得概述的是，D3 是一个基于数据操作文档的 JavaScript 库，生态系统中有许多贡献者，因此可用的数据可视化数量是巨大的。了解基础知识将使我们能够以相对较少的努力提供真正令人印象深刻的结果。

使用 FHLS 格式，我们可以说服图表软件接受我们的数据，就好像它是 OHLC 格式的一样。因此，我们应该搜索互联网上可以使用的 D3 OHLC 库。在这个例子中，我们选择了[techanjs.org](http://techanjs.org/)，因为它不仅提供 OHLC，还提供了一些其他可能在以后有用的可视化。

实现 D3 代码通常就是将其剪切并粘贴到一个文本文件中，修改源代码中的任何数据目录路径。如果您以前从未在这个领域工作过，下面有一些有用的提示，可以帮助您入门：

+   如果您正在使用 Chrome 浏览器的 Web 技术，可以在****选项** | **更多工具** | **开发者工具**** 下找到一组非常有用的工具。即使没有其他内容，这也将提供您尝试运行的代码的错误输出，否则将会丢失，使得调试空白页面的结果更加容易。

+   如果您的代码使用单个文件，就像下面的示例一样，请始终使用`index.html`作为文件名。

+   如果您的代码引用本地文件，通常在实现 D3 时会这样，您需要运行一个 Web 服务器，以便它们可以被提供。默认情况下，Web 浏览器无法访问本地文件，因为存在固有的安全风险（恶意代码访问本地文件）。运行 Web 服务器的简单方法是在代码的源目录中执行：`nohup python -m SimpleHTTPServer &`。绝对不要让浏览器访问本地文件，因为这将使其完全暴露于攻击之下。例如，不要运行：`chrome --allow-file-access-from-files`

+   在源代码中使用 D3 时，尽可能始终使用`<script src="img/d3.v4.min.js"></script>`来确保导入库的最新版本。

我们可以直接使用代码，唯一需要改变的是引用列的方式：

```scala
data = data.slice(0, 200).map(function(d) {
  return {
    date: parseDate(d.start),
    open: +d.firstPrice,
    high: +d.HighestHighPrice,
    low: +d.LowestLowPrice,
    close: +d.SecondPrice
  };
});
```

这将产生一个类似于这样的图表：

![可视化数据](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_007.jpg)

在这个图表上，绿色的条表示从**第一个**低价到**第二个**高价的增加，红色的条表示从**第一个高价**到**第二个低价**的减少。这种与典型 OHLC 图表的微妙变化至关重要。一眼就能看到时间序列在总结条上的上升和下降流动。这有助于我们理解价格在我们固定的查询尺度或窗口大小上的上升和下降流动，而无需像在原始价格值的线图上那样解释时间尺度的影响。结果图表提供了一种减少较小时间框架上的噪音的方法，以一种整洁且可重复的方式对我们的时间序列进行可视化总结。然而，我们仍然可以做更多。

### 带有反转的 FHLS

我们之前使用我们的 TrendCalculus 方程计算了趋势反转，并将其与上面的 FHLS 摘要数据一起绘制，这将真正增强我们的可视化效果，显示高/低条和趋势反转点。我们可以通过修改我们的 D3 代码来实现 D3 散点图代码。所需的代码可以在互联网上的许多地方找到，就像以前一样；我们下面有一些代码，可以通过将相关部分添加到`<script>`中来集成。

添加`reversalPrice`字段：

```scala
data = data.slice(0, 200).map(function(d) {
  return {
    date: parseDate(d.start),
    open: +d.firstPrice,
    high: +d.HighestHighPrice,
    low: +d.LowestLowPrice,
    close: +d.secondPrice,
    price: +d.reversalPrice
  };
}).sort(function(a, b) {
  return d3.ascending(accessor.d(a), accessor.d(b));
});
```

并绘制点：

```scala
svg.selectAll(".dot")
  .data(data)
  .enter().append("circle")
  .attr("class", "dot")
  .attr("r", 1)
  .attr("cx", function(d) { return x(d.date); })
  .attr("cy", function(d) { return y(d.price); })
  .style("fill","black"); 
```

一旦成功集成，我们将看到一个类似于这样的图表：

![带有反转的 FHLS](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_008.jpg)

或者，反转可以使用简单的折线图非常有效。以下是一个这样的图表示例，用于演示趋势反转绘图的视觉影响：

![带有反转的 FHLS](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_009.jpg)

### 边界情况

在我们之前的计算中，我们简要提到在执行简单趋势算法时可能产生值 0。根据我们的算法，这可能发生在以下情况下：

+   sign ( -1 + (+1) )

+   sign ( +1 + (-1) )

+   sign ( 0 + (0) )

通过一个示例图，我们可以使用我们的算法识别出以下值：

![边界情况](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_010.jpg)

### 注意

在货币市场中，我们可以将每个窗口识别为内部条或外部条。内部是定义市场不确定性的条，没有更高的高点或更低的低点。外部是已经达到更高的高点或更低的低点；当然，这些术语只能在数据可用时分配。

到目前为止，我们所看到的这些零似乎会破坏我们的算法。然而，事实并非如此，实际上有一个有效的解决方案，使我们能够考虑到它们。

#### 零值

在审查以前的图表时，我们可以想象价格在 FHLS 条形图上所走过的路径，这一过程变得容易，因为绿色条表示时间上的价格上涨，红色条表示时间上的价格下跌。了解时间路径如何帮助解决零趋势问题？有一个简单的答案，但不一定直观。

我们之前一直记录了我们数据处理过程中所有高点和低点的日期；尽管我们没有使用所有的日期。我们使用这些日期计算出的**第一个**和**第二**值实际上指示了该局部趋势的流动或方向，如下图所示，一旦你研究了一段时间的摘要图表，你的眼睛自然会随着这种流动来解释时间序列：

![零值](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_011.jpg)

如果我们看下一个图表，我们会发现我们的眼睛如何解释时间流动的虚线不仅仅是暗示的。在我们的日期高点和低点之间，有一些数据值没有被我们特别构建的条形图总结，这意味着条形图之间存在时间间隙。我们可以利用这一特性来解决问题。考虑以下图表，加上价格线：

![零值](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_012.jpg)

#### 填补间隙

使用同一个示例的延续，我们将取出一个已识别的间隙，并演示我们可以用来填补它们的方法：

![填补间隙](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_013.jpg)

步骤如下：

+   找到 0 趋势（内/外部条）

+   为了填补由于从前一个窗口借用第二个值和从当前窗口借用第一个值而暗示的间隙，插入一个新的 FHLS 摘要（见前面的图表）

+   在正常的 FHLS 构建过程中发出这些特殊的条形图，按照常规的高/低窗口格式化它们，并使用它们以正常的方式找到趋势

现在我们已经创建了一个新的条形图，我们可以以已定义的方式使用它；我们方程式的一个标志（高差或低差）将有一个值为 0，另一个现在将是+1 或-1。然后进行反转计算。在前面的例子中，问号在我们的新系统下变成了-1，因为我们找到了一个更低的低点；因此最后一个高点是一个反转。

我们可以修改代码，从我们之前的努力中的`simpleTrendDF`开始：

1.  过滤所有标志为 0 的行。

`val zeroSignRowsDF = simpleTrendDF.filter("sign == 0")`.

1.  删除 sign 列，因为我们将使用这个新 DataFrame 的模式。

`val zeroRowsDF = zeroSignRowsDF.drop("sign")`.

1.  迭代每一行并输出已经以以下方式修改的更新行：

窗口开始日期是`highLowPrev`列中**第二**个值的日期

`window.end`日期可以保持不变，因为它在 FHLS 计算中没有被使用。

`highLow`条目构造如下：

1.  `HighestHighDate`：**第一个**`highLow`日期和**第二**`highLowPrev`日期中较早的日期

1.  `HighestHighPrice`：与上述相关的价格

1.  `LowestLowDate`：**第一个**`highLow`日期和**第二**`highLowPrev`日期中较晚的日期

1.  `LowestLowPrice`：与上述相关的价格

1.  `firstPrice`：与最早的新`highLow`日期相关的价格

1.  `secondPrice`：与最新的`highLow`日期相关的价格

`highLowPrev`列可以保留，因为它将在下一步中被删除

```scala
val tempHighLowDF =
spark.createDataFrame(highLowDF.rdd.map(x => {
               RowFactory.create(x.getAs("window")., x.getAs("highLow"),
                                 x.getAs("highLowPrev"))

             }), highLowDF.schema)
```

1.  删除`highLowPrev`列

`val newHighLowDF = tempHighLowDF.drop("highLowPrev")`

1.  将新的 DataFrame 与`highLowDF`联合，这将插入新的行

`val updatedHighLowDF = newHighLowDF.union(highLowDF)`

1.  继续使用`updatedHighLowDF`而不是`highLowDF`进行简单的趋势处理，并从以下开始：

`val sortedWindow = Window.orderBy("window.start")`

继续前面的例子，我们可以看到（可能）不再有零值，反转仍然清晰且快速计算。如果选择的时间窗口非常小，例如秒或分钟，则输出中可能仍然有零值，表明价格在该时段内没有变化。可以重复间隙处理，或者将窗口的大小更改为延长静态价格期间的大小：

![填补间隙](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_014.jpg)

我们已经使用 D3 看到了时间序列，但现在可以使用图表软件来显示新添加的覆盖隐含间隙的条形图，这些条形图显示在下图中的白色条形图中。总体结果非常直观，我们可以很容易地用肉眼看到趋势及其反转：

![填补间隙](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-spark-ds/img/image_12_015.jpg)

### 可堆叠处理

现在我们有了这个功能，我们可以将趋势反转列表视为算法的第二次输入。为此，我们可以调整我们的窗口函数，使输入成为 N 个有序观察的窗口，而不是固定的时间块。如果这样做，我们可以*堆叠*并创建多尺度*趋势树* TrendCalculus，这意味着我们可以将算法的输出反馈到后续的处理中。这将创建一个多尺度的反转查找器。以这种*堆叠*的方式进行多次处理是一种高效的过程，因为后续处理中固有的数据减少。通过多次运行，分区会自下而上地构建成一个分层结构。通过这种方式工作，我们可以使用这种方法来根据我们需要的详细程度*缩放*长期和短期的趋势范围；随着我们*缩放*，趋势模式变得更容易用肉眼看到。

从我们的`reversalsDF` DataFrame 中选择相关数据将使我们能够简单地再次运行该过程；`highLow`列包含：

+   `HighestHigh`的日期和价格

+   `LowestLow`的日期和价格

可以选择并输出为一个包含（日期，价格）的文件；正是我们用来摄取原始文件的格式：

```scala
val newColumnNames = Seq("DATE", "PRICE")

val highLowHighestDF = simpleTrendDF.select("highLow.HighestHighDate", "highLow.HighestHighPrice").toDF(newColumnNames:_*)

val highLowLowestDF = simpleTrendDF.select("highLow.LowestLowDate", "highLow.LowestLowPrice").toDF(newColumnNames:_*)

val stackedDF = highLowHighestDF.union(highLowLowestDF)

stackedDF.write
     .option("header", "true")
     .csv("stackData.csv")
```

让我们回顾一下我们已经构建的内容：

+   我们已经构建了代码来处理时间序列，并有效地将其总结为固定时间窗口内的日期高点和低点

+   我们已经为每个时间窗口分配了正向或负向趋势

+   我们有一种处理边缘情况的方法，消除了零值趋势问题

+   我们有一个计算方法来找到实际的时间点，以及趋势反转发生时的价格数值。

这样做的效果是，我们构建了一种非常快速的代理方法，可以将我们的时间序列简化为类似分段线性回归的压缩形式。从另一个角度来看，趋势逆转列表代表了我们的时间序列的简化形式，忽略了小时间尺度上的噪音。

# 实际应用

现在我们已经编写了我们的算法，让我们看看这种方法在真实数据上的实际应用。我们将首先了解算法的性能，以便确定我们可能在哪里使用它。

## 算法特性

那么，这种算法的特点是什么？以下是其优势和劣势的列表。

### 优点

优点如下：

+   该算法是通用的，非常适合基于流和 Spark 的实现。

+   该理论简单而有效

+   实现速度快且高效

+   结果是可视化和可解释的

+   该方法可堆叠，并允许进行多尺度研究；在使用 Spark 窗口时非常简单

### 缺点

缺点如下：

+   滞后指标，该算法找到了过去发生的趋势逆转，并不能直接用于预测趋势变化

+   滞后累积到更高的尺度，意味着需要更多的数据（因此需要更多的时间滞后）才能找到长期趋势变化，而不是在较短时间尺度上找到趋势逆转

了解该算法的局限性很重要。我们已经创建了一个非常有用的分析工具，可用于研究趋势。但是，它本身并不是一个预测工具，而是一个更容易识别趋势以进行后续处理的工具。

## 可能的用例

有了我们新发现的将时间序列转换为变化点列表的能力，许多曾经困难的用例变得容易。让我们看看一些潜在的应用。

### 图表注释

我们可以在趋势变化发生时，即在主要高点或低点，从 GDELT feed 中检索新闻标题，从而为我们的图表添加上下文。

### 共同趋势

我们可以利用噪音的减少来比较不同时间序列的趋势，并设计计算来衡量哪些是共同趋势。

### 数据减少

我们可以使用该算法简化时间序列并减少数据量，同时保留关键时刻，堆叠该算法可以实现更大的减少。

### 索引

我们可以将变化点视为时间序列的一种新形式的指数，例如，允许检索数据的部分，其中短时间内的事物与长时间内的趋势相反。

### 分形维度

我们可以在不同的时间尺度上找到变化点，并使用信息来研究时间序列的分形维度。

### 分段线性回归的流式代理

该方法可以作为计算分段线性回归的一种非常快速的方法，需要这种方法时。

# 总结

在本章中，我们介绍了使用 TrendCalculus 分析趋势的方法。我们概述了尽管趋势分析是一个非常常见的用例，但除了非常通用的可视化软件外，几乎没有工具可以帮助数据科学家进行这种分析。我们引导读者了解了 TrendCalculus 算法，演示了我们如何在 Spark 中实现理论的高效可扩展性。我们描述了识别算法的关键输出的过程：在命名尺度上的趋势逆转。在计算了逆转之后，我们使用 D3.js 可视化了已经总结为一周窗口的时间序列数据，并绘制了趋势逆转。本章继续解释了如何克服主要的边缘情况：在简单趋势计算中发现的零值。最后，我们简要概述了算法特性和潜在用例，演示了该方法是优雅的，可以在 Spark 中轻松描述和实现。

在下一章中，我们将揭秘数据安全的话题。我们将从数据科学的角度描述安全的最重要领域，集中讨论高度机密数据处理的理论和实施授权访问。
