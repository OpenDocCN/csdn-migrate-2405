# Python Web 爬虫秘籍（三）

> 原文：[`zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089`](https://zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：执行词形还原

如何做

+   一些过程，比如我们将使用的过程，需要额外下载它们用于执行各种分析的各种数据集。可以通过执行以下操作来下载它们：安装 NLTK

+   安装 NLTK

+   ![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/75aae6dd-a071-42ea-a6be-8ccd5f961b95.png)NTLK GUI

+   执行词干提取

+   首先我们从 NLTK 导入句子分词器：

+   识别和删除短词

+   句子分割的第一个例子在`07/01_sentence_splitting1.py`文件中。这使用 NLTK 中内置的句子分割器，该分割器使用内部边界检测算法：

+   识别和删除罕见单词

+   然后使用`sent_tokenize`分割句子，并报告句子：

+   我们按照以下步骤进行：

+   介绍

+   您可以使用语言参数选择所需的语言。例如，以下内容将基于德语进行分割：

+   阅读和清理工作列表中的描述

# 挖掘数据通常是工作中最有趣的部分，文本是最常见的数据来源之一。我们将使用 NLTK 工具包介绍常见的自然语言处理概念和统计模型。我们不仅希望找到定量数据，比如我们已经抓取的数据中的数字，还希望能够分析文本信息的各种特征。这种文本信息的分析通常被归类为自然语言处理（NLP）的一部分。Python 有一个名为 NLTK 的库，提供了丰富的功能。我们将调查它的几种功能。

在 Mac 上，这实际上会弹出以下窗口：

# 如何做

NLTK 的核心可以使用 pip 安装：

# 从 StackOverflow 抓取工作列表

文本整理和分析

1.  选择安装所有并按下下载按钮。工具将开始下载许多数据集。这可能需要一段时间，所以喝杯咖啡或啤酒，然后不时地检查一下。完成后，您就可以继续进行下一个步骤了。

```py
pip install nltk
```

1.  执行句子分割

```py
import nltk nltk.download() showing info https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/index.xml
```

1.  删除标点符号

在本章中，我们将涵盖：

执行标记化

# 在这个配方中，我们学习安装 Python 的自然语言工具包 NTLK。

许多 NLP 过程需要将大量文本分割成句子。这可能看起来是一个简单的任务，但对于计算机来说可能会有问题。一个简单的句子分割器可以只查找句号（。），或者使用其他算法，比如预测分类器。我们将使用 NLTK 来检查两种句子分割的方法。

# 这将产生以下输出：

我们将使用存储在`07/sentence1.txt`文件中的句子。它包含以下内容，这些内容是从 StackOverflow 上的随机工作列表中提取的：

我们正在寻找具有以下经验的开发人员：ASP.NET，C＃，SQL Server 和 AngularJS。我们是一个快节奏，高度迭代的团队，必须随着我们的工厂的增长迅速适应。我们需要那些习惯于解决新问题，创新解决方案，并且每天与公司的各个方面进行互动的人。有创意，有动力，能够承担责任并支持您创建的应用程序。帮助我们更快地将火箭送出去！

识别和删除停用词

1.  从 StackOverflow 工作列表创建词云

```py
from nltk.tokenize import sent_tokenize
```

1.  然后加载文件：

```py
with open('sentence1.txt', 'r') as myfile:
  data=myfile.read().replace('\n', '')
```

1.  拼接 n-gram

```py
sentences = sent_tokenize(data)   for s in sentences:
  print(s)
```

如果您想创建自己的分词器并自己训练它，那么可以使用`PunktSentenceTokenizer`类。`sent_tokenize`实际上是这个类的派生类，默认情况下实现了英语的句子分割。但是您可以从 17 种不同的语言模型中选择：

```py
We are seeking developers with demonstrable experience in: ASP.NET, C#, SQL Server, and AngularJS.
We are a fast-paced, highly iterative team that has to adapt quickly as our factory grows.
We need people who are comfortable tackling new problems, innovating solutions, and interacting with every facet of the company on a daily basis.
Creative, motivated, able to take responsibility and support the applications you create.
Help us get rockets out the door faster!
```

1.  执行句子分割

```py
Michaels-iMac-2:~ michaelheydt$ ls ~/nltk_data/tokenizers/punkt PY3   finnish.pickle  portuguese.pickle README   french.pickle  slovene.pickle czech.pickle  german.pickle  spanish.pickle danish.pickle  greek.pickle  swedish.pickle dutch.pickle  italian.pickle  turkish.pickle english.pickle  norwegian.pickle estonian.pickle  polish.pickle
```

1.  计算单词的频率分布

```py
sentences = sent_tokenize(data, language="german") 
```

# 还有更多...

要了解更多关于这个算法的信息，可以阅读[`citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.85.5017&rep=rep1&type=pdf`](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.85.5017&rep=rep1&type=pdf)上提供的源论文。

# 执行标记化

标记化是将文本转换为标记的过程。这些标记可以是段落、句子和常见的单词，通常是基于单词级别的。NLTK 提供了许多标记器，将在本教程中进行演示。

# 如何做

这个示例的代码在`07/02_tokenize.py`文件中。它扩展了句子分割器，演示了五种不同的标记化技术。文件中的第一句将是唯一被标记化的句子，以便我们保持输出的数量在合理范围内：

1.  第一步是简单地使用内置的 Python 字符串`.split()`方法。结果如下：

```py
print(first_sentence.split())
['We', 'are', 'seeking', 'developers', 'with', 'demonstrable', 'experience', 'in:', 'ASP.NET,', 'C#,', 'SQL', 'Server,', 'and', 'AngularJS.'] 
```

句子是在空格边界上分割的。注意，诸如“:”和“,”之类的标点符号包括在生成的标记中。

1.  以下演示了如何使用 NLTK 中内置的标记器。首先，我们需要导入它们：

```py
from nltk.tokenize import word_tokenize, regexp_tokenize, wordpunct_tokenize, blankline_tokenize
```

以下演示了如何使用`word_tokenizer`：

```py
print(word_tokenize(first_sentence))
['We', 'are', 'seeking', 'developers', 'with', 'demonstrable', 'experience', 'in', ':', 'ASP.NET', ',', 'C', '#', ',', 'SQL', 'Server', ',', 'and', 'AngularJS', '.'] 
```

结果现在还将标点符号分割为它们自己的标记。

以下使用了正则表达式标记器，它允许您将任何正则表达式表达为标记器。它使用了一个`'\w+'`正则表达式，结果如下：

```py
print(regexp_tokenize(first_sentence, pattern='\w+')) ['We', 'are', 'seeking', 'developers', 'with', 'demonstrable', 'experience', 'in', 'ASP', 'NET', 'C', 'SQL', 'Server', 'and', 'AngularJS']
```

`wordpunct_tokenizer`的结果如下：

```py
print(wordpunct_tokenize(first_sentence))
['We', 'are', 'seeking', 'developers', 'with', 'demonstrable', 'experience', 'in', ':', 'ASP', '.', 'NET', ',', 'C', '#,', 'SQL', 'Server', ',', 'and', 'AngularJS', '.']
```

`blankline_tokenize`产生了以下结果：

```py
print(blankline_tokenize(first_sentence))
['We are seeking developers with demonstrable experience in: ASP.NET, C#, SQL Server, and AngularJS.']
```

可以看到，这并不是一个简单的问题。根据被标记化的文本类型的不同，你可能会得到完全不同的结果。

# 执行词干提取

词干提取是将标记减少到其*词干*的过程。从技术上讲，它是将屈折（有时是派生）的单词减少到它们的词干形式的过程-单词的基本根形式。例如，单词*fishing*、*fished*和*fisher*都来自根词*fish*。这有助于将被处理的单词集合减少到更容易处理的较小基本集合。

最常见的词干提取算法是由 Martin Porter 创建的，NLTK 提供了 PorterStemmer 中这个算法的实现。NLTK 还提供了 Snowball 词干提取器的实现，这也是由 Porter 创建的，旨在处理英语以外的其他语言。NLTK 还提供了一个名为 Lancaster 词干提取器的实现。Lancaster 词干提取器被认为是这三种中最激进的词干提取器。

# 如何做

NLTK 在其 PorterStemmer 类中提供了 Porter 词干提取算法的实现。可以通过以下代码轻松创建一个实例：

```py
>>> from nltk.stem import PorterStemmer
>>> pst = PorterStemmer() >>> pst.stem('fishing') 'fish'
```

`07/03_stemming.py`文件中的脚本将 Porter 和 Lancaster 词干提取器应用于我们输入文件的第一句。执行词干提取的主要部分是以下内容：

```py
pst = PorterStemmer() lst = LancasterStemmer() print("Stemming results:")   for token in regexp_tokenize(sentences[0], pattern='\w+'):
  print(token, pst.stem(token), lst.stem(token))
```

结果如下：

```py
Stemming results:
We We we
are are ar
seeking seek seek
developers develop develop
with with with
demonstrable demonstr demonst
experience experi expery
in in in
ASP asp asp
NET net net
C C c
SQL sql sql
Server server serv
and and and
AngularJS angularj angulars
```

从结果可以看出，Lancaster 词干提取器确实比 Porter 词干提取器更激进，因为后者将几个单词进一步缩短了。

# 执行词形还原

词形还原是一个更系统的过程，将单词转换为它们的基本形式。词干提取通常只是截断单词的末尾，而词形还原考虑了单词的形态分析，评估上下文和词性以确定屈折形式，并在不同规则之间做出决策以确定词根。

# 如何做

在 NTLK 中可以使用`WordNetLemmatizer`进行词形还原。这个类使用 WordNet 服务，一个在线语义数据库来做出决策。`07/04_lemmatization.py`文件中的代码扩展了之前的词干提取示例，还计算了每个单词的词形还原。重要的代码如下：

```py
from nltk.stem import PorterStemmer
from nltk.stem.lancaster import LancasterStemmer
from nltk.stem import WordNetLemmatizer

pst = PorterStemmer() lst = LancasterStemmer() wnl = WordNetLemmatizer()   print("Stemming / lemmatization results") for token in regexp_tokenize(sentences[0], pattern='\w+'):
  print(token, pst.stem(token), lst.stem(token), wnl.lemmatize(token))
```

结果如下：

```py
Stemming / lemmatization results
We We we We
are are ar are
seeking seek seek seeking
developers develop develop developer
with with with with
demonstrable demonstr demonst demonstrable
experience experi expery experience
in in in in
ASP asp asp ASP
NET net net NET
C C c C
SQL sql sql SQL
Server server serv Server
and and and and
AngularJS angularj angulars AngularJS
```

使用词形还原过程的结果有一些差异。这表明，根据您的数据，其中一个可能比另一个更适合您的需求，因此如果需要，可以尝试所有这些方法。

# 确定和去除停用词

停用词是在自然语言处理情境中不提供太多上下文含义的常见词。这些词通常是语言中最常见的词。这些词在英语中至少包括冠词和代词，如*I*，*me*，*the*，*is*，*which*，*who*，*at*等。在处理文档中的含义时，通常可以通过在处理之前去除这些词来方便处理，因此许多工具都支持这种能力。NLTK 就是其中之一，并且支持大约 22 种语言的停用词去除。

# 如何做

按照以下步骤进行（代码在`07/06_freq_dist.py`中可用）：

1.  以下演示了使用 NLTK 去除停用词。首先，从导入停用词开始：

```py
>>> from nltk.corpus import stopwords
```

1.  然后选择所需语言的停用词。以下选择英语：

```py
>>> stoplist = stopwords.words('english')
```

1.  英语停用词列表有 153 个单词：

```py
>>> len(stoplist) 153
```

1.  这不是太多，我们可以在这里展示它们所有：

```py
>>> stoplist
 ['i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', 'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his', 'himself', 'she', 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against', 'between', 'into', 'through', 'during', 'before', 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on', 'off', 'over', 'under', 'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't', 'can', 'will', 'just', 'don', 'should', 'now', 'd', 'll', 'm', 'o', 're', 've', 'y', 'ain', 'aren', 'couldn', 'didn', 'doesn', 'hadn', 'hasn', 'haven', 'isn', 'ma', 'mightn', 'mustn', 'needn', 'shan', 'shouldn', 'wasn', 'weren', 'won', 'wouldn']
```

1.  从单词列表中去除停用词可以通过简单的 Python 语句轻松完成。这在`07/05_stopwords.py`文件中有演示。脚本从所需的导入开始，并准备好我们要处理的句子：

```py
from nltk.tokenize import sent_tokenize
from nltk.tokenize import regexp_tokenize
from nltk.corpus import stopwords

with open('sentence1.txt', 'r') as myfile:
  data = myfile.read().replace('\n', '')   sentences = sent_tokenize(data) first_sentence = sentences[0]   print("Original sentence:") print(first_sentence)
```

1.  这产生了我们熟悉的以下输出：

```py
Original sentence:
We are seeking developers with demonstrable experience in: ASP.NET, C#, SQL Server, and AngularJS.
```

1.  然后我们对该句子进行标记化：

```py
tokenized = regexp_tokenize(first_sentence, '\w+') print("Tokenized:", tokenized)
```

1.  使用以下输出：

```py
Tokenized: ['We', 'are', 'seeking', 'developers', 'with', 'demonstrable', 'experience', 'in', 'ASP', 'NET', 'C', 'SQL', 'Server', 'and', 'AngularJS']
```

1.  然后我们可以使用以下语句去除停用词列表中的标记：

```py
stoplist = stopwords.words('english') cleaned = [word for word in tokenized if word not in stoplist] print("Cleaned:", cleaned)
```

使用以下输出：

```py
Cleaned: ['We', 'seeking', 'developers', 'demonstrable', 'experience', 'ASP', 'NET', 'C', 'SQL', 'Server', 'AngularJS']
```

# 还有更多...

去除停用词有其目的。这是有帮助的，正如我们将在后面的一篇文章中看到的，我们将在那里创建一个词云（停用词在词云中不提供太多信息），但也可能是有害的。许多其他基于句子结构推断含义的自然语言处理过程可能会因为去除停用词而受到严重阻碍。

# 计算单词的频率分布

频率分布计算不同数据值的出现次数。这些对我们很有价值，因为我们可以用它们来确定文档中最常见的单词或短语，从而推断出哪些具有更大或更小的价值。

可以使用几种不同的技术来计算频率分布。我们将使用内置在 NLTK 中的工具来进行检查。

# 如何做

NLTK 提供了一个类，`ntlk.probabilities.FreqDist`，可以让我们非常容易地计算列表中值的频率分布。让我们使用这个类来进行检查（代码在`07/freq_dist.py`中）：

1.  要使用 NLTK 创建频率分布，首先从 NTLK 中导入该功能（还有标记器和停用词）：

```py
from nltk.probabilities import FreqDist
from nltk.tokenize import regexp_tokenize
from nltk.corpus import stopwords
```

1.  然后我们可以使用`FreqDist`函数根据单词列表创建频率分布。我们将通过读取`wotw.txt`（《世界大战》- 古腾堡出版社提供）的内容，对其进行标记化并去除停用词来进行检查：

```py
with open('wotw.txt', 'r') as file:
  data = file.read() tokens = [word.lower() for word in regexp_tokenize(data, '\w+')] stoplist = stopwords.words('english') without_stops = [word for word in tokens if word not in stoplist]
```

1.  然后我们可以计算剩余单词的频率分布：

```py
freq_dist = FreqDist(without_stops)
```

1.  `freq_dist`是一个单词到单词计数的字典。以下打印了所有这些单词（只显示了几行输出，因为有成千上万个唯一单词）：

```py
print('Number of words: %s' % len(freq_dist)) for key in freq_dist.keys():
  print(key, freq_dist[key])
**Number of words: 6613
shall 8
dwell 1
worlds 2
inhabited 1
lords 1
world 26
things 64**
```

1.  我们可以使用频率分布来识别最常见的单词。以下报告了最常见的 10 个单词：

```py
print(freq_dist.most_common(10))
[('one', 201), ('upon', 172), ('said', 166), ('martians', 164), ('people', 159), ('came', 151), ('towards', 129), ('saw', 129), ('man', 126), ('time', 122)] 
```

我希望火星人在前 5 名中。它是第 4 名。

# 还有更多...

我们还可以使用这个来识别最不常见的单词，通过使用`.most_common()`的负值进行切片。例如，以下内容找到了最不常见的 10 个单词：

```py
print(freq_dist.most_common()[-10:])
[('bitten', 1), ('gibber', 1), ('fiercer', 1), ('paler', 1), ('uglier', 1), ('distortions', 1), ('haunting', 1), ('mockery', 1), ('beds', 1), ('seers', 1)]
```

有相当多的单词只出现一次，因此这只是这些值的一个子集。只出现一次的单词数量可以通过以下方式确定（由于有 3,224 个单词，已截断）：

```py
dist_1 = [item[0] for item in freq_dist.items() if item[1] == 1] print(len(dist_1), dist_1)

3224 ['dwell', 'inhabited', 'lords', 'kepler', 'quoted', 'eve', 'mortal', 'scrutinised', 'studied', 'scrutinise', 'multiply', 'complacency', 'globe', 'infusoria', ...
```

# 识别和去除罕见单词

我们可以通过利用查找低频词的能力来删除低频词，这些词在某个领域中属于正常范围之外，或者只是从给定领域中被认为是罕见的单词列表中删除。但我们将使用的技术对两者都适用。

# 如何做

罕见单词可以通过构建一个罕见单词列表然后从正在处理的标记集中删除它们来移除。罕见单词列表可以通过使用 NTLK 提供的频率分布来确定。然后您决定应该使用什么阈值作为罕见单词的阈值：

1.  `07/07_rare_words.py` 文件中的脚本扩展了频率分布配方，以识别出现两次或更少的单词，然后从标记中删除这些单词：

```py
with open('wotw.txt', 'r') as file:
  data = file.read()   tokens = [word.lower() for word in regexp_tokenize(data, '\w+')] stoplist = stopwords.words('english') without_stops = [word for word in tokens if word not in stoplist]   freq_dist = FreqDist(without_stops)   print('Number of words: %s' % len(freq_dist))   # all words with one occurrence dist = [item[0] for item in freq_dist.items() if item[1] <= 2] print(len(dist)) not_rare = [word for word in without_stops if word not in dist]   freq_dist2 = FreqDist(not_rare) print(len(freq_dist2))
```

输出结果为：

```py
Number of words: 6613
4361
2252
```

通过这两个步骤，删除停用词，然后删除出现 2 次或更少的单词，我们将单词的总数从 6,613 个减少到 2,252 个，大约是原来的三分之一。

# 识别和删除罕见单词

删除短单词也可以用于去除内容中的噪声单词。以下内容检查了删除特定长度或更短单词。它还演示了通过选择不被视为短的单词（长度超过指定的短单词长度）来进行相反操作。

# 如何做

我们可以利用 NLTK 的频率分布有效地计算短单词。我们可以扫描源中的所有单词，但扫描结果分布中所有键的长度会更有效，因为它将是一个显著较小的数据集：

1.  `07/08_short_words.py` 文件中的脚本举例说明了这个过程。它首先加载了 `wotw.txt` 的内容，然后计算了单词频率分布（删除短单词后）。然后它识别了三个字符或更少的单词：

```py
short_word_len = 3 short_words = [word for word in freq_dist.keys() if len(word) <= short_word_len] print('Distinct # of words of len <= %s: %s' % (short_word_len, len(short_words))) 
```

这将导致：

```py
Distinct # of words of len <= 3: 184
```

1.  通过更改列表推导中的逻辑运算符可以找到不被视为短的单词：

```py
unshort_words = [word for word in freq_dist.keys() if len(word) > short_word_len] print('Distinct # of word > len %s: %s' % (short_word_len, len(unshort_words)))
```

结果为：

```py
Distinct # of word > len 3: 6429
```

# 删除标点符号

根据使用的分词器和这些分词器的输入，可能希望从生成的标记列表中删除标点符号。`regexp_tokenize` 函数使用 `'\w+'` 作为表达式可以很好地去除标点符号，但 `word_tokenize` 做得不太好，会将许多标点符号作为它们自己的标记返回。

# 如何做

通过列表推导和仅选择不是标点符号的项目，类似于从标记中删除其他单词的标点符号的删除。`07/09_remove_punctuation.py` 文件演示了这一点。让我们一起走过这个过程：

1.  我们将从以下开始，它将从工作列表中`word_tokenize`一个字符串：

```py
>>> content = "Strong programming experience in C#, ASP.NET/MVC, JavaScript/jQuery and SQL Server" >>> tokenized = word_tokenize(content) >>> stop_list = stopwords.words('english') >>> cleaned = [word for word in tokenized if word not in stop_list] >>> print(cleaned)
['Strong', 'programming', 'experience', 'C', '#', ',', 'ASP.NET/MVC', ',', 'JavaScript/jQuery', 'SQL', 'Server'] 
```

1.  现在我们可以用以下方法去除标点符号：

```py
>>> punctuation_marks = [':', ',', '.', "``", "''", '(', ')', '-', '!', '#'] >>> tokens_cleaned = [word for word in cleaned if word not in punctuation_marks] >>> print(tokens_cleaned)
['Strong', 'programming', 'experience', 'C', 'ASP.NET/MVC', 'JavaScript/jQuery', 'SQL', 'Server']
```

1.  这个过程可以封装在一个函数中。以下是在 `07/punctuation.py` 文件中，将删除标点符号：

```py
def remove_punctuation(tokens):
  punctuation = [':', ',', '.', "``", "''", '(', ')', '-', '!', '#']
  return [token for token in tokens if token not in punctuation]
```

# 还有更多...

删除标点符号和符号可能是一个困难的问题。虽然它们对许多搜索没有价值，但标点符号也可能需要保留作为标记的一部分。以搜索工作网站并尝试找到 C# 编程职位为例，就像在这个配方中的示例一样。C# 的标记化被分成了两个标记：

```py
>>> word_tokenize("C#") ['C', '#']
```

实际上我们有两个问题。将 C 和 # 分开后，我们失去了 C# 在源内容中的信息。然后，如果我们从标记中删除 #，那么我们也会失去这些信息，因为我们也无法从相邻的标记中重建 C#。

# 拼接 n-gram

关于 NLTK 被用于识别文本中的 n-gram 已经写了很多。n-gram 是文档/语料库中常见的一组单词，长度为*n*个单词（出现 2 次或更多）。2-gram 是任何常见的两个单词，3-gram 是一个三个单词的短语，依此类推。我们不会研究如何确定文档中的 n-gram。我们将专注于从我们的标记流中重建已知的 n-gram，因为我们认为这些 n-gram 对于搜索结果比任何顺序中找到的 2 个或 3 个独立单词更重要。

在解析工作列表的领域中，重要的 2-gram 可能是诸如**计算机科学**、**SQL Server**、**数据科学**和**大数据**之类的东西。此外，我们可以将 C#视为`'C'`和`'#'`的 2-gram，因此在处理工作列表时，我们可能不希望使用正则表达式解析器或`'#'`作为标点符号。

我们需要有一个策略来识别我们的标记流中的这些已知组合。让我们看看如何做到这一点。

# 如何做到这一点

首先，这个例子并不打算进行详尽的检查或者最佳性能的检查。只是一个简单易懂的例子，可以轻松应用和扩展到我们解析工作列表的例子中：

1.  我们将使用来自`StackOverflow` SpaceX 的工作列表的以下句子来检查这个过程：

*我们正在寻找具有以下方面经验的开发人员：ASP.NET、C#、SQL Server 和 AngularJS。我们是一个快节奏、高度迭代的团队，随着我们的工厂的增长，我们必须快速适应。*

1.  这两个句子中有许多高价值的 2-gram（我认为工作列表是寻找 2-gram 的好地方）。仅仅看一下，我就可以挑出以下内容是重要的：

+   +   ASP.NET

+   C#

+   SQL Server

+   快节奏

+   高度迭代

+   快速适应

+   可证明的经验

1.  现在，虽然这些在技术上的定义可能不是 2-gram，但当我们解析它们时，它们都将被分开成独立的标记。这可以在`07/10-ngrams.py`文件中显示，并在以下示例中显示：

```py
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

with open('job-snippet.txt', 'r') as file:
  data = file.read()   tokens = [word.lower() for word in word_tokenize(data)] stoplist = stopwords.words('english') without_stops = [word for word in tokens if word not in stoplist] print(without_stops)
```

这产生了以下输出：

```py
['seeking', 'developers', 'demonstrable', 'experience', ':', 'asp.net', ',', 'c', '#', ',', 'sql', 'server', ',', 'angularjs', '.', 'fast-paced', ',', 'highly', 'iterative', 'team', 'adapt', 'quickly', 'factory', 'grows', '.']
```

我们希望从这个集合中去掉标点，但我们希望在构建一些 2-gram 之后再去做，特别是这样我们可以将"C#"拼接成一个单个标记。

1.  `07/10-reconstruct-2grams.py`文件中的脚本演示了一个函数来实现这一点。首先，我们需要描述我们想要重建的 2-gram。在这个文件中，它们被定义为以下内容：

```py
grams = {
  "c": [{"#": ""}],
  "sql": [{"server": " "}],
  "fast": [{"paced": "-"}],
  "highly": [{"iterative": " "}],
  "adapt": [{"quickly": " "}],
  "demonstrable": [{"experience", " "}]
}
```

`grams`是一个字典，其中键指定了 2-gram 的“左”侧。每个键都有一个字典列表，其中每个字典键可以是 2-gram 的右侧，值是将放在左侧和右侧之间的字符串。

1.  有了这个定义，我们能够看到我们的标记中的`"C"`和`"#"`被重构为"C#"。`"SQL"`和`"Server"`将成为`"SQL Server"`。`"fast"`和`"paced"`将导致`"faced-paced"`。

所以我们只需要一个函数来使这一切工作。这个函数在`07/buildgrams.py`文件中定义：

```py
def build_2grams(tokens, patterns):
  results = []
  left_token = None
 for i, t in enumerate(tokens):
  if left_token is None:
  left_token = t
            continue    right_token = t

        if left_token.lower() in patterns:
  right = patterns[left_token.lower()]
  if right_token.lower() in right:
  results.append(left_token + right[right_token.lower()] + right_token)
  left_token = None
 else:
  results.append(left_token)
  else:
  results.append(left_token)
  left_token = right_token

    if left_token is not None:
  results.append(left_token)
  return results
```

1.  这个函数，给定一组标记和一个以前描述的格式的字典，将返回一组修订后的标记，其中任何匹配的 2-gram 都被放入一个单个标记中。以下演示了它的一些简单用法：

```py
grams = {
  'c': {'#': ''} } print(build_2grams(['C'], grams)) print(build_2grams(['#'], grams)) print(build_2grams(['C', '#'], grams)) print(build_2grams(['c', '#'], grams))
```

这导致以下输出：

```py
['C']
['#']
['C#']
['c#']
```

1.  现在让我们将其应用到我们的输入中。这个完整的脚本在`07/10-reconstruct-2grams.py`文件中（并添加了一些 2-gram）：

```py
grams = {
  "c": {"#": ""},
  "sql": {"server": " "},
  "fast": {"paced": "-"},
  "highly": {"iterative": " "},
  "adapt": {"quickly": " "},
  "demonstrable": {"experience": " "},
  "full": {"stack": " "},
  "enterprise": {"software": " "},
  "bachelor": {"s": "'"},
  "computer": {"science": " "},
  "data": {"science": " "},
  "current": {"trends": " "},
  "real": {"world": " "},
  "paid": {"relocation": " "},
  "web": {"server": " "},
  "relational": {"database": " "},
  "no": {"sql": " "} }   with open('job-snippet.txt', 'r') as file:
  data = file.read()   tokens = word_tokenize(data) stoplist = stopwords.words('english') without_stops = [word for word in tokens if word not in stoplist] result = remove_punctuation(build_2grams(without_stops, grams)) print(result)
```

结果如下：

```py
['We', 'seeking', 'developers', 'demonstrable experience', 'ASP.NET', 'C#', 'SQL Server', 'AngularJS', 'We', 'fast-paced', 'highly iterative', 'team', 'adapt quickly', 'factory', 'grows']
```

完美！

# 还有更多...

我们向`build_2grams()`函数提供一个字典，该字典定义了识别 2-gram 的规则。在这个例子中，我们预定义了这些 2-gram。可以使用 NLTK 来查找 2-gram（以及一般的 n-gram），但是在这个小样本的一个工作职位中，可能找不到任何 2-gram。

# 从 StackOverflow 抓取工作列表

现在让我们将一些内容整合起来，从 StackOverflow 的工作列表中获取信息。这次我们只看一个列表，这样我们就可以了解这些页面的结构并从中获取信息。在后面的章节中，我们将研究如何从多个列表中聚合结果。现在让我们学习如何做到这一点。

# 准备就绪

实际上，StackOverflow 使得从他们的页面中抓取数据变得非常容易。我们将使用来自[`stackoverflow.com/jobs/122517/spacex-enterprise-software-engineer-full-stack-spacex?so=p&sec=True&pg=1&offset=22&cl=Amazon%3b+`](https://stackoverflow.com/jobs/122517/spacex-enterprise-software-engineer-full-stack-spacex?so=p&sec=True&pg=1&offset=22&cl=Amazon%3b+)的内容。在您阅读时，这可能不再可用，因此我已经在`07/spacex-job-listing.html`文件中包含了此页面的 HTML，我们将在本章的示例中使用。

StackOverflow 的工作列表页面非常有结构。这可能是因为它们是由程序员创建的，也是为程序员创建的。页面（在撰写本文时）看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/dfb46fdc-eb94-4b80-93a8-885f9ce8a756.png)StackOverflow 工作列表

所有这些信息都被编码在页面的 HTML 中。您可以通过分析页面内容自行查看。但 StackOverflow 之所以如此出色的原因在于它将其大部分页面数据放在一个嵌入的 JSON 对象中。这是放置在`<script type="application/ld+json>`HTML 标签中的，所以很容易找到。下面显示了此标签的截断部分（描述被截断，但所有标记都显示出来）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/5fecad0b-3acf-4cb6-90d9-4da452fd469b.png)工作列表中嵌入的 JSON

这使得获取内容非常容易，因为我们可以简单地检索页面，找到这个标签，然后使用`json`库将此 JSON 转换为 Python 对象。除了实际的工作描述，还包括了工作发布的大部分“元数据”，如技能、行业、福利和位置信息。我们不需要在 HTML 中搜索信息-只需找到这个标签并加载 JSON。请注意，如果我们想要查找项目，比如工作职责**，我们仍然需要解析描述。还要注意，描述包含完整的 HTML，因此在解析时，我们仍需要处理 HTML 标记。

# 如何做到这一点

让我们去获取这个页面的工作描述。我们将在下一个示例中对其进行清理。

这个示例的完整代码在`07/12_scrape_job_stackoverflow.py`文件中。让我们来看一下：

1.  首先我们读取文件：

```py
with open("spacex-job-listing.txt", "r") as file:
  content = file.read()
```

1.  然后，我们将内容加载到`BeautifulSoup`对象中，并检索`<script type="application/ld+json">`标签：

```py
bs = BeautifulSoup(content, "lxml") script_tag = bs.find("script", {"type": "application/ld+json"})
```

1.  现在我们有了这个标签，我们可以使用`json`库将其内容加载到 Python 字典中：

```py
job_listing_contents = json.loads(script_tag.contents[0]) print(job_listing_contents)
```

这个输出看起来像下面这样（为了简洁起见，这是截断的）：

```py
{'@context': 'http://schema.org', '@type': 'JobPosting', 'title': 'SpaceX Enterprise Software Engineer, Full Stack', 'skills': ['c#', 'sql', 'javascript', 'asp.net', 'angularjs'], 'description': '<h2>About this job</h2>\r\n<p><span>Location options: <strong>Paid relocation</strong></span><br/><span>Job type: <strong>Permanent</strong></span><br/><span>Experience level: <strong>Mid-Level, Senior</strong></span><br/><span>Role: <strong>Full Stack Developer</strong></span><br/><span>Industry: <strong>Aerospace, Information Technology, Web Development</strong></span><br/><span>Company size: <strong>1k-5k people</strong></span><br/><span>Company type: <strong>Private</strong></span><br/></p><br/><br/><h2>Technologies</h2> <p>c#, sql, javascript, asp.net, angularjs</p> <br/><br/><h2>Job description</h2> <p><strong>Full Stack Enterprise&nbsp;Software Engineer</strong></p>\r\n<p>The EIS (Enterprise Information Systems) team writes the software that builds rockets and powers SpaceX. We are responsible for 
```

1.  这很棒，因为现在我们可以做一些简单的任务，而不涉及 HTML 解析。例如，我们可以仅使用以下代码检索工作所需的技能：

```py
# print the skills for skill in job_listing_contents["skills"]:
  print(skill)
```

它产生以下输出：

```py
c#
sql
javascript
asp.net
angularjs
```

# 还有更多...

描述仍然存储在此 JSON 对象的描述属性中的 HTML 中。我们将在下一个示例中检查该数据的解析。

# 阅读和清理工作列表中的描述

工作列表的描述仍然是 HTML。我们将要从这些数据中提取有价值的内容，因此我们需要解析这个 HTML 并执行标记化、停用词去除、常用词去除、进行一些技术 2-gram 处理，以及一般的所有这些不同的过程。让我们来做这些。

# 准备就绪

我已经将确定基于技术的 2-gram 的代码折叠到`07/tech2grams.py`文件中。我们将在文件中使用`tech_2grams`函数。

# 如何做...

这个示例的代码在`07/13_clean_jd.py`文件中。它延续了`07/12_scrape_job_stackoverflow.py`文件的内容：

1.  我们首先从我们加载的描述的描述键创建一个`BeautifulSoup`对象。我们也会打印出来看看它是什么样子的：

```py
desc_bs = BeautifulSoup(job_listing_contents["description"], "lxml") print(desc_bs) <p><span>Location options: <strong>Paid relocation</strong></span><br/><span>Job type: <strong>Permanent</strong></span><br/><span>Experience level: <strong>Mid-Level, Senior</strong></span><br/><span>Role: <strong>Full Stack Developer</strong></span><br/><span>Industry: <strong>Aerospace, Information Technology, Web Development</strong></span><br/><span>Company size: <strong>1k-5k people</strong></span><br/><span>Company type: <strong>Private</strong></span><br/></p><br/><br/><h2>Technologies</h2> <p>c#, sql, javascript, asp.net, angularjs</p> <br/><br/><h2>Job description</h2> <p><strong>Full Stack Enterprise Software Engineer</strong></p>
<p>The EIS (Enterprise Information Systems) team writes the software that builds rockets and powers SpaceX. We are responsible for all of the software on the factory floor, the warehouses, the financial systems, the restaurant, and even the public home page. Elon has called us the "nervous system" of SpaceX because we connect all of the other teams at SpaceX to ensure that the entire rocket building process runs smoothly.</p>
<p><strong>Responsibilities:</strong></p>
<ul>
<li>We are seeking developers with demonstrable experience in: ASP.NET, C#, SQL Server, and AngularJS. We are a fast-paced, highly iterative team that has to adapt quickly as our factory grows. We need people who are comfortable tackling new problems, innovating solutions, and interacting with every facet of the company on a daily basis. Creative, motivated, able to take responsibility and support the applications you create. Help us get rockets out the door faster!</li>
</ul>
<p><strong>Basic Qualifications:</strong></p>
<ul>
<li>Bachelor's degree in computer science, engineering, physics, mathematics, or similar technical discipline.</li>
<li>3+ years of experience developing across a full-stack:  Web server, relational database, and client-side (HTML/Javascript/CSS).</li>
</ul>
<p><strong>Preferred Skills and Experience:</strong></p>
<ul>
<li>Database - Understanding of SQL. Ability to write performant SQL. Ability to diagnose queries, and work with DBAs.</li>
<li>Server - Knowledge of how web servers operate on a low-level. Web protocols. Designing APIs. How to scale web sites. Increase performance and diagnose problems.</li>
<li>UI - Demonstrated ability creating rich web interfaces using a modern client side framework. Good judgment in UX/UI design.  Understands the finer points of HTML, CSS, and Javascript - know which tools to use when and why.</li>
<li>System architecture - Knowledge of how to structure a database, web site, and rich client side application from scratch.</li>
<li>Quality - Demonstrated usage of different testing patterns, continuous integration processes, build deployment systems. Continuous monitoring.</li>
<li>Current - Up to date with current trends, patterns, goings on in the world of web development as it changes rapidly. Strong knowledge of computer science fundamentals and applying them in the real-world.</li>
</ul> <br/><br/></body></html>
```

1.  我们想要浏览一遍，去掉所有的 HTML，只留下描述的文本。然后我们将对其进行标记。幸运的是，使用`BeautifulSoup`很容易就能去掉所有的 HTML 标签：

```py
just_text = desc_bs.find_all(text=True) print(just_text)

['About this job', '\n', 'Location options: ', 'Paid relocation', 'Job type: ', 'Permanent', 'Experience level: ', 'Mid-Level, Senior', 'Role: ', 'Full Stack Developer', 'Industry: ', 'Aerospace, Information Technology, Web Development', 'Company size: ', '1k-5k people', 'Company type: ', 'Private', 'Technologies', ' ', 'c#, sql, javascript, asp.net, angularjs', ' ', 'Job description', ' ', 'Full Stack Enterprise\xa0Software Engineer', '\n', 'The EIS (Enterprise Information Systems) team writes the software that builds rockets and powers SpaceX. We are responsible for all of the software on the factory floor, the warehouses, the financial systems, the restaurant, and even the public home page. Elon has called us the "nervous system" of SpaceX because we connect all of the other teams at SpaceX to ensure that the entire rocket building process runs smoothly.', '\n', 'Responsibilities:', '\n', '\n', 'We are seeking developers with demonstrable experience in: ASP.NET, C#, SQL Server, and AngularJS. We are a fast-paced, highly iterative team that has to adapt quickly as our factory grows. We need people who are comfortable tackling new problems, innovating solutions, and interacting with every facet of the company on a daily basis. Creative, motivated, able to take responsibility and support the applications you create. Help us get rockets out the door faster!', '\n', '\n', 'Basic Qualifications:', '\n', '\n', "Bachelor's degree in computer science, engineering, physics, mathematics, or similar technical discipline.", '\n', '3+ years of experience developing across a full-stack:\xa0 Web server, relational database, and client-side (HTML/Javascript/CSS).', '\n', '\n', 'Preferred Skills and Experience:', '\n', '\n', 'Database - Understanding of SQL. Ability to write performant SQL. Ability to diagnose queries, and work with DBAs.', '\n', 'Server - Knowledge of how web servers operate on a low-level. Web protocols. Designing APIs. How to scale web sites. Increase performance and diagnose problems.', '\n', 'UI - Demonstrated ability creating rich web interfaces using a modern client side framework. Good judgment in UX/UI design.\xa0 Understands the finer points of HTML, CSS, and Javascript - know which tools to use when and why.', '\n', 'System architecture - Knowledge of how to structure a database, web site, and rich client side application from scratch.', '\n', 'Quality - Demonstrated usage of different testing patterns, continuous integration processes, build deployment systems. Continuous monitoring.', '\n', 'Current - Up to date with current trends, patterns, goings on in the world of web development as it changes rapidly. Strong knowledge of computer science fundamentals and applying them in the real-world.', '\n', ' ']
```

太棒了！我们现在已经有了这个，它已经被分解成可以被视为句子的部分！

1.  让我们把它们全部连接在一起，对它们进行词标记，去掉停用词，并应用常见的技术工作 2-gram：

```py
joined = ' '.join(just_text) tokens = word_tokenize(joined)   stop_list = stopwords.words('english') with_no_stops = [word for word in tokens if word not in stop_list] cleaned = remove_punctuation(two_grammed) print(cleaned)
```

这样就会得到以下输出：

```py
['job', 'Location', 'options', 'Paid relocation', 'Job', 'type', 'Permanent', 'Experience', 'level', 'Mid-Level', 'Senior', 'Role', 'Full-Stack', 'Developer', 'Industry', 'Aerospace', 'Information Technology', 'Web Development', 'Company', 'size', '1k-5k', 'people', 'Company', 'type', 'Private', 'Technologies', 'c#', 'sql', 'javascript', 'asp.net', 'angularjs', 'Job', 'description', 'Full-Stack', 'Enterprise Software', 'Engineer', 'EIS', 'Enterprise', 'Information', 'Systems', 'team', 'writes', 'software', 'builds', 'rockets', 'powers', 'SpaceX', 'responsible', 'software', 'factory', 'floor', 'warehouses', 'financial', 'systems', 'restaurant', 'even', 'public', 'home', 'page', 'Elon', 'called', 'us', 'nervous', 'system', 'SpaceX', 'connect', 'teams', 'SpaceX', 'ensure', 'entire', 'rocket', 'building', 'process', 'runs', 'smoothly', 'Responsibilities', 'seeking', 'developers', 'demonstrable experience', 'ASP.NET', 'C#', 'SQL Server', 'AngularJS', 'fast-paced', 'highly iterative', 'team', 'adapt quickly', 'factory', 'grows', 'need', 'people', 'comfortable', 'tackling', 'new', 'problems', 'innovating', 'solutions', 'interacting', 'every', 'facet', 'company', 'daily', 'basis', 'Creative', 'motivated', 'able', 'take', 'responsibility', 'support', 'applications', 'create', 'Help', 'us', 'get', 'rockets', 'door', 'faster', 'Basic', 'Qualifications', 'Bachelor', "'s", 'degree', 'computer science', 'engineering', 'physics', 'mathematics', 'similar', 'technical', 'discipline', '3+', 'years', 'experience', 'developing', 'across', 'full-stack', 'Web server', 'relational database', 'client-side', 'HTML/Javascript/CSS', 'Preferred', 'Skills', 'Experience', 'Database', 'Understanding', 'SQL', 'Ability', 'write', 'performant', 'SQL', 'Ability', 'diagnose', 'queries', 'work', 'DBAs', 'Server', 'Knowledge', 'web', 'servers', 'operate', 'low-level', 'Web', 'protocols', 'Designing', 'APIs', 'scale', 'web', 'sites', 'Increase', 'performance', 'diagnose', 'problems', 'UI', 'Demonstrated', 'ability', 'creating', 'rich', 'web', 'interfaces', 'using', 'modern', 'client-side', 'framework', 'Good', 'judgment', 'UX/UI', 'design', 'Understands', 'finer', 'points', 'HTML', 'CSS', 'Javascript', 'know', 'tools', 'use', 'System', 'architecture', 'Knowledge', 'structure', 'database', 'web', 'site', 'rich', 'client-side', 'application', 'scratch', 'Quality', 'Demonstrated', 'usage', 'different', 'testing', 'patterns', 'continuous integration', 'processes', 'build', 'deployment', 'systems', 'Continuous monitoring', 'Current', 'date', 'current trends', 'patterns', 'goings', 'world', 'web development', 'changes', 'rapidly', 'Strong', 'knowledge', 'computer science', 'fundamentals', 'applying', 'real-world']
```

我认为这是从工作清单中提取出来的一组非常好的和精细的关键词。


# 第八章：搜索、挖掘和可视化数据

在本章中，我们将涵盖：

+   IP 地址地理编码

+   收集维基百科编辑的 IP 地址

+   在维基百科上可视化贡献者位置频率

+   从 StackOverflow 工作列表创建词云

+   在维基百科上爬取链接

+   在维基百科上可视化页面关系

+   计算维基百科页面之间的分离度

# 介绍

在本章中，我们将研究如何搜索 Web 内容，推导分析结果，并可视化这些结果。我们将学习如何定位内容的发布者并可视化其位置的分布。然后，我们将研究如何爬取、建模和可视化维基百科页面之间的关系。

# IP 地址地理编码

地理编码是将地址转换为地理坐标的过程。这些地址可以是实际的街道地址，可以使用各种工具进行地理编码，例如 Google 地图地理编码 API（[`developers.google.com/maps/documentation/geocoding/intro`](https://developers.google.com/maps/documentation/geocoding/intro)）。 IP 地址可以通过各种应用程序进行地理编码，以确定计算机及其用户的位置。一个非常常见和有价值的用途是分析 Web 服务器日志，以确定您网站的用户来源。

这是可能的，因为 IP 地址不仅代表计算机的地址，可以与该计算机进行通信，而且通常还可以通过在 IP 地址/位置数据库中查找来转换为大致的物理位置。有许多这些数据库可用，所有这些数据库都由各种注册机构（如 ICANN）维护。还有其他工具可以报告公共 IP 地址的地理位置。

有许多免费的 IP 地理位置服务。我们将研究一个非常容易使用的服务，即 freegeoip.net。

# 准备工作

Freegeoip.net 是一个免费的地理编码服务。如果您在浏览器中转到[`www.freegeoip.net`](http://www.freegeoip.net)，您将看到一个类似以下的页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/9f56e0c3-c452-4ab1-b951-aa839cfdc831.png)freegeoip.net 主页

默认页面报告您的公共 IP 地址，并根据其数据库给出 IP 地址的地理位置。这并不准确到我家的实际地址，实际上相差几英里，但在世界上的一般位置是相当准确的。我们可以使用这种分辨率甚至更低的数据做重要的事情。通常，只知道 Web 请求的国家来源对于许多目的已经足够了。

Freegeoip 允许您每小时进行 15000 次调用。每次页面加载都算一次调用，正如我们将看到的，每次 API 调用也算一次。

# 如何做到这一点

我们可以爬取这个页面来获取这些信息，但幸运的是，freegeoip.net 为我们提供了一个方便的 REST API 来使用。在页面下方滚动，我们可以看到 API 文档：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/89c10af1-bbcf-4f28-ba1f-5d13fb0f706f.png)freegeoio.net API 文档

我们可以简单地使用 requests 库使用正确格式的 URL 进行 GET 请求。例如，只需在浏览器中输入以下 URL，即可返回给定 IP 地址的地理编码数据的 JSON 表示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/f87e77ef-910e-4011-b99f-c7942469aa52.png)IP 地址的示例 JSON

一个 Python 脚本，用于演示这一点，可以在`08/01_geocode_address.py`中找到。这很简单，包括以下内容：

```py
import json
import requests

raw_json = requests.get("http://www.freegeoip.net/json/63.153.113.92").text
parsed = json.loads(raw_json) print(json.dumps(parsed, indent=4, sort_keys=True)) 
```

这有以下输出：

```py
{
    "city": "Deer Lodge",
    "country_code": "US",
    "country_name": "United States",
    "ip": "63.153.113.92",
    "latitude": 46.3797,
    "longitude": -112.7202,
    "metro_code": 754,
    "region_code": "MT",
    "region_name": "Montana",
    "time_zone": "America/Denver",
    "zip_code": "59722"
}
```

请注意，对于这个 IP 地址，您的输出可能会有所不同，并且不同的 IP 地址肯定会有所不同。

# 如何收集维基百科编辑的 IP 地址

处理地理编码 IP 地址的聚合结果可以提供有价值的见解。这在服务器日志中非常常见，也可以在许多其他情况下使用。许多网站包括内容贡献者的 IP 地址。维基百科提供了他们所有页面的更改历史。由维基百科未注册用户创建的编辑在历史中公布其 IP 地址。我们将研究如何创建一个爬虫，以浏览给定维基百科主题的历史，并收集未注册编辑的 IP 地址。

# 准备工作

我们将研究对维基百科的 Web 抓取页面所做的编辑。此页面位于：[`en.wikipedia.org/wiki/Web_scraping`](https://en.wikipedia.org/wiki/Web_scraping)。以下是此页面的一小部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/533c554f-85a6-4f21-bea7-c382ae64db39.png)查看历史选项卡

注意右上角的查看历史。单击该链接可访问编辑历史：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/11286403-7354-45f0-9786-49148c1f52dc.png)检查 IP 地址

我把这个滚动了一点，以突出一个匿名编辑。请注意，我们可以使用源中的`mw-userling mw-anonuserlink`类来识别这些匿名编辑条目。

还要注意，您可以指定要列出的每页编辑的数量，可以通过向 URL 添加参数来指定。以下 URL 将给我们最近的 500 次编辑：

[`en.wikipedia.org/w/index.php?title=Web_scraping&offset=&limit=500&action=history`](https://en.wikipedia.org/w/index.php?title=Web_scraping&offset=&limit=500&action=history)

因此，我们不是爬行多个不同的页面，每次走 50 个，而是只做一个包含 500 个页面。

# 操作方法

我们按以下步骤进行：

1.  执行抓取的代码在脚本文件`08/02_geocode_wikipedia_edits.py`中。运行脚本会产生以下输出（截断到前几个地理 IP）：

```py
Reading page: https://en.wikipedia.org/w/index.php?title=Web_scraping&offset=&limit=500&action=history
Got 106 ip addresses
{'ip': '2601:647:4a04:86d0:1cdf:8f8a:5ca5:76a0', 'country_code': 'US', 'country_name': 'United States', 'region_code': 'CA', 'region_name': 'California', 'city': 'Sunnyvale', 'zip_code': '94085', 'time_zone': 'America/Los_Angeles', 'latitude': 37.3887, 'longitude': -122.0188, 'metro_code': 807}
{'ip': '194.171.56.13', 'country_code': 'NL', 'country_name': 'Netherlands', 'region_code': '', 'region_name': '', 'city': '', 'zip_code': '', 'time_zone': 'Europe/Amsterdam', 'latitude': 52.3824, 'longitude': 4.8995, 'metro_code': 0}
{'ip': '109.70.55.226', 'country_code': 'DK', 'country_name': 'Denmark', 'region_code': '85', 'region_name': 'Zealand', 'city': 'Roskilde', 'zip_code': '4000', 'time_zone': 'Europe/Copenhagen', 'latitude': 55.6415, 'longitude': 12.0803, 'metro_code': 0}
{'ip': '101.177.247.131', 'country_code': 'AU', 'country_name': 'Australia', 'region_code': 'TAS', 'region_name': 'Tasmania', 'city': 'Lenah Valley', 'zip_code': '7008', 'time_zone': 'Australia/Hobart', 'latitude': -42.8715, 'longitude': 147.2751, 'metro_code': 0}

```

脚本还将地理 IP 写入`geo_ips.json`文件。下一个示例将使用该文件，而不是再次进行所有页面请求。

# 工作原理

解释如下。脚本首先执行以下代码：

```py
if __name__ == "__main__":
  geo_ips = collect_geo_ips('Web_scraping', 500)
  for geo_ip in geo_ips:
  print(geo_ip)
  with open('geo_ips.json', 'w') as outfile:
  json.dump(geo_ips, outfile)
```

调用`collect_geo_ips`，该函数将请求指定主题的页面和最多 500 次编辑。然后将这些地理 IP 打印到控制台，并写入`geo_ips.json`文件。

`collect_geo_ips`的代码如下：

```py
def collect_geo_ips(article_title, limit):
  ip_addresses = get_history_ips(article_title, limit)
  print("Got %s ip addresses" % len(ip_addresses))
  geo_ips = get_geo_ips(ip_addresses)
  return geo_ips
```

此函数首先调用`get_history_ips`，报告找到的数量，然后对每个 IP 地址重复请求`get_geo_ips`。

`get_history_ips`的代码如下：

```py
def get_history_ips(article_title, limit):
  history_page_url = "https://en.wikipedia.org/w/index.php?title=%s&offset=&limit=%s&action=history" % (article_title, limit)
  print("Reading page: " + history_page_url)
  html = requests.get(history_page_url).text
    soup = BeautifulSoup(html, "lxml")    anon_ip_anchors = soup.findAll("a", {"class": "mw-anonuserlink"})
  addresses = set()
  for ip in anon_ip_anchors:
  addresses.add(ip.get_text())
  return addresses
```

这个函数构建了历史页面的 URL，检索页面，然后提取所有具有`mw-anonuserlink`类的不同 IP 地址。

然后，`get_geo_ips`获取这组 IP 地址，并对每个 IP 地址调用`freegeoip.net`以获取数据。

```py
def get_geo_ips(ip_addresses):
  geo_ips = []
  for ip in ip_addresses:
  raw_json = requests.get("http://www.freegeoip.net/json/%s" % ip).text
        parsed = json.loads(raw_json)
  geo_ips.append(parsed)
  return geo_ips
```

# 还有更多...

虽然这些数据很有用，但在下一个示例中，我们将读取写入`geo_ips.json`的数据（使用 pandas），并使用条形图可视化用户按国家的分布。

# 在维基百科上可视化贡献者位置频率

我们可以使用收集的数据来确定来自世界各地的维基百科文章的编辑频率。这可以通过按国家对捕获的数据进行分组并计算与每个国家相关的编辑数量来完成。然后，我们将对数据进行排序并创建一个条形图来查看结果。

# 操作方法

这是一个使用 pandas 执行的非常简单的任务。示例的代码在`08/03_visualize_wikipedia_edits.py`中。

1.  代码开始导入 pandas 和`matplotlib.pyplot`：

```py
>>> import pandas as pd
>>> import matplotlib.pyplot as plt
```

1.  我们在上一个示例中创建的数据文件已经以可以直接被 pandas 读取的格式。这是使用 JSON 作为数据格式的好处之一；pandas 内置支持从 JSON 读取和写入数据。以下使用`pd.read_json()`函数读取数据并在控制台上显示前五行：

```py
>>> df = pd.read_json("geo_ips.json") >>> df[:5]) city country_code country_name ip latitude \
0 Hanoi VN Vietnam 118.70.248.17 21.0333 
1 Roskilde DK Denmark 109.70.55.226 55.6415 
2 Hyderabad IN India 203.217.144.211 17.3753 
3 Prague CZ Czechia 84.42.187.252 50.0833 
4 US United States 99.124.83.153 37.7510

longitude metro_code region_code region_name time_zone \
0 105.8500 0 HN Thanh Pho Ha Noi Asia/Ho_Chi_Minh 
1 12.0803 0 85 Zealand Europe/Copenhagen 
2 78.4744 0 TG Telangana Asia/Kolkata 
3 14.4667 0 10 Hlavni mesto Praha Europe/Prague 
4 -97.8220 0
zip_code 
0 
1 4000 
2 
3 130 00 
4
```

1.  对于我们的直接目的，我们只需要`country_code`列，我们可以用以下方法提取它（并显示该结果中的前五行）：

```py
>>> countries_only = df.country_code
>>> countries_only[:5]

0 VN
1 DK
2 IN
3 CZ
4 US
Name: country_code, dtype:object
```

1.  现在我们可以使用`.groupby('country_code')`来对这个系列中的行进行分组，然后在结果上，`调用.count()`将返回每个组中的项目数。该代码还通过`调用.sort_values()`将结果从最大到最小值进行排序：

```py
>>> counts = df.groupby('country_code').country_code.count().sort_values(ascending=False) >>> counts[:5]

country_code
US 28
IN 12
BR 7
NL 7
RO 6
Name: country_code, dtype: int64 
```

仅从这些结果中，我们可以看出美国在编辑方面绝对领先，印度是第二受欢迎的。

这些数据可以很容易地可视化为条形图：

```py
counts.plot(kind='bar') plt.show()
```

这导致以下条形图显示所有国家的总体分布：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/3c71176f-4d78-4576-9b9d-63f6df781f6a.png)编辑频率的直方图

# 从 StackOverflow 职位列表创建词云

现在让我们来看看如何创建一个词云。词云是一种展示一组文本中关键词频率的图像。图像中的单词越大，它在文本中的重要性就越明显。

# 准备工作

我们将使用 Word Cloud 库来创建我们的词云。该库的源代码可在[`github.com/amueller/word_cloud`](https://github.com/amueller/word_cloud)上找到。这个库可以通过`pip install wordcloud`安装到你的 Python 环境中。

# 如何做到这一点

创建词云的脚本在`08/04_so_word_cloud.py`文件中。这个示例是从第七章的堆栈溢出示例中继续提供数据的可视化。

1.  首先从 NLTK 中导入词云和频率分布函数：

```py
from wordcloud import WordCloud
from nltk.probability import FreqDist
```

1.  然后，词云是从我们从职位列表中收集的单词的概率分布生成的：

```py
freq_dist = FreqDist(cleaned) wordcloud = WordCloud(width=1200, height=800).generate_from_frequencies(freq_dist) 
```

现在我们只需要显示词云：

```py
import matplotlib.pyplot as plt
plt.imshow(wordcloud, interpolation='bilinear') plt.axis("off") plt.show()
```

生成的词云如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/02a14763-b72f-4386-ae29-ebed2d7d7219.png)职位列表的词云

位置和大小都有一些内置的随机性，所以你得到的结果可能会有所不同。

# 在维基百科上爬取链接

在这个示例中，我们将编写一个小程序来利用爬取维基百科页面上的链接，通过几个深度级别。在这个爬取过程中，我们将收集页面之间以及每个页面引用的页面之间的关系。在此过程中，我们将建立这些页面之间的关系，最终在下一个示例中进行可视化。

# 准备工作

这个示例的代码在`08/05_wikipedia_scrapy.py`中。它引用了代码示例中`modules`/`wikipedia`文件夹中的一个模块的代码，所以确保它在你的 Python 路径中。

# 如何做到这一点

你可以使用示例 Python 脚本。它将使用 Scrapy 爬取单个维基百科页面。它将爬取的页面是 Python 页面，网址为[`en.wikipedia.org/wiki/Python_(programming_language)`](https://en.wikipedia.org/wiki/Python_(programming_language))，并收集该页面上的相关链接。

运行时，你将看到类似以下的输出：

```py
/Users/michaelheydt/anaconda/bin/python3.6 /Users/michaelheydt/Dropbox/Packt/Books/PyWebScrCookbook/code/py/08/05_wikipedia_scrapy.py
parsing: https://en.wikipedia.org/wiki/Python_(programming_language)
parsing: https://en.wikipedia.org/wiki/C_(programming_language)
parsing: https://en.wikipedia.org/wiki/Object-oriented_programming
parsing: https://en.wikipedia.org/wiki/Ruby_(programming_language)
parsing: https://en.wikipedia.org/wiki/Go_(programming_language)
parsing: https://en.wikipedia.org/wiki/Java_(programming_language)
------------------------------------------------------------
0 Python_(programming_language) C_(programming_language)
0 Python_(programming_language) Java_(programming_language)
0 Python_(programming_language) Go_(programming_language)
0 Python_(programming_language) Ruby_(programming_language)
0 Python_(programming_language) Object-oriented_programming
```

输出的第一部分来自 Scrapy 爬虫，并显示传递给解析方法的页面。这些页面以我们的初始页面开头，并通过该页面的前五个最常见的链接。

此输出的第二部分是对被爬取的页面以及在该页面上找到的链接的表示，这些链接被认为是未来处理的。第一个数字是找到关系的爬取级别，然后是父页面和在该页面上找到的链接。对于每个找到的页面/链接，都有一个单独的条目。由于这是一个深度爬取，我们只显示从初始页面找到的页面。

# 它是如何工作的

让我们从主脚本文件`08/05_wikipedia_scrapy.py`中的代码开始。这是通过创建一个`WikipediaSpider`对象并运行爬取开始的：

```py
process = CrawlerProcess({
    'LOG_LEVEL': 'ERROR',
    'DEPTH_LIMIT': 1 })

process.crawl(WikipediaSpider)
spider = next(iter(process.crawlers)).spider
process.start()
```

这告诉 Scrapy 我们希望运行一层深度，我们得到一个爬虫的实例，因为我们想要检查其属性，这些属性是爬取的结果。然后用以下方法打印结果：

```py
print("-"*60)

for pm in spider.linked_pages:
    print(pm.depth, pm.title, pm.child_title)
```

爬虫的每个结果都存储在`linked_pages`属性中。每个对象都由几个属性表示，包括页面的标题（维基百科 URL 的最后部分）和在该页面的 HTML 内容中找到的每个页面的标题。

现在让我们来看一下爬虫的功能。爬虫的代码在`modules/wikipedia/spiders.py`中。爬虫首先定义了一个 Scrapy `Spider`的子类：

```py
class WikipediaSpider(Spider):
    name = "wikipedia"
  start_urls = [ "https://en.wikipedia.org/wiki/Python_(programming_language)" ]
```

我们从维基百科的 Python 页面开始。接下来是定义一些类级变量，以定义爬取的操作方式和要检索的结果：

```py
page_map = {}
linked_pages = []
max_items_per_page = 5 max_crawl_depth = 1
```

这次爬取的每个页面都将由爬虫的解析方法处理。让我们来看一下。它从以下开始：

```py
def parse(self, response):
    print("parsing: " + response.url)

    links = response.xpath("//*/a[starts-with(@href, '/wiki/')]/@href")

    link_counter = {}
```

在每个维基百科页面中，我们寻找以`/wiki`开头的链接。页面中还有其他链接，但这些是这次爬取将考虑的重要链接。

这个爬虫实现了一个算法，其中页面上找到的所有链接都被计算为相似。有相当多的重复链接。其中一些是虚假的。其他代表了多次链接到其他页面的真正重要性。

`max_items_per_page`定义了我们将进一步调查当前页面上有多少链接。每个页面上都会有相当多的链接，这个算法会计算所有相似的链接并将它们放入桶中。然后它会跟踪`max_items_per_page`最受欢迎的链接。

这个过程是通过使用`links_counter`变量来管理的。这是当前页面和页面上找到的所有链接之间的映射字典。对于我们决定跟踪的每个链接，我们计算它在页面上被引用的次数。这个变量是该 URL 和计数引用次数的对象之间的映射：

```py
class LinkReferenceCount:
    def __init__(self, link):
        self.link = link
  self.count = 0
```

然后，代码遍历所有识别的链接：

```py
for l in links:
    link = l.root
    if ":" not in link and "International" not in link and link != self.start_urls[0]:
        if link not in link_counter:
            link_counter[link] = LinkReferenceCount(link)
        link_counter[link].count += 1
```

这个算法检查每个链接，并根据规则（链接中没有“：”，也没有“国际”因为它非常受欢迎所以我们排除它，最后我们不包括起始 URL）只考虑它们进行进一步的爬取。如果链接通过了这一步，那么就会创建一个新的`LinkReferenceCounter`对象（如果之前没有看到这个链接），或者增加它的引用计数。

由于每个页面上可能有重复的链接，我们只想考虑`max_items_per_page`最常见的链接。代码通过以下方式实现了这一点：

```py
references = list(link_counter.values())
s = sorted(references, key=lambda x: x.count, reverse=True)
top = s[:self.max_items_per_page]
```

从`link_counter`字典中，我们提取所有的`LinkReferenceCounter`对象，并按计数排序，然后选择前`max_items_per_page`个项目。

下一步是对这些符合条件的项目进行记录，记录在类的`linked_pages`字段中。这个列表中的每个对象都是`PageToPageMap`类型。这个类有以下定义：

```py
class PageToPageMap:
    def __init__(self, link, child_link, depth): #, parent):
  self.link = link
  self.child_link = child_link
  self.title = self.get_page_title(self.link)
        self.child_title = self.get_page_title(self.child_link)
        self.depth = depth    def get_page_title(self, link):
        parts = link.split("/")
        last = parts[len(parts)-1]
        label = urllib.parse.unquote(last)
        return label
```

从根本上说，这个对象表示一个源页面 URL 到一个链接页面 URL，并跟踪爬取的当前级别。标题属性是维基百科 URL 最后部分的 URL 解码形式，代表了 URL 的更加人性化的版本。

最后，代码将新的页面交给 Scrapy 进行爬取。

```py
for item in top:
    new_request = Request("https://en.wikipedia.org" + item.link,
                          callback=self.parse, meta={ "parent": pm })
    yield new_request
```

# 还有更多...

这个爬虫/算法还跟踪爬取中当前的**深度**级别。如果认为新链接超出了爬取的最大深度。虽然 Scrapy 可以在一定程度上控制这一点，但这段代码仍然需要排除超出最大深度的链接。

这是通过使用`PageToPageMap`对象的深度字段来控制的。对于每个爬取的页面，我们检查响应是否具有元数据，这是表示给定页面的“父”`PageToPageMap`对象的属性。我们可以通过以下代码找到这个：

```py
depth = 0 if "parent" in response.meta:
    parent = response.meta["parent"]
    depth = parent.depth + 1
```

页面解析器中的此代码查看是否有父对象。只有爬取的第一个页面没有父页面。如果有一个实例，这个爬取的深度被认为是更高的。当创建新的`PageToPageMap`对象时，这个值被传递并存储。

代码通过使用请求对象的 meta 属性将此对象传递到爬取的下一级别：

```py
meta={ "parent": pm }
```

通过这种方式，我们可以将数据从 Scrapy 蜘蛛的一个爬取级别传递到下一个级别。

# 在维基百科上可视化页面关系

在这个示例中，我们使用之前收集的数据，并使用 NetworkX Python 库创建一个力导向网络可视化页面关系。

# 准备工作

NetworkX 是用于建模、可视化和分析复杂网络关系的软件。您可以在[`networkx.github.io`](https://networkx.github.io/)找到更多关于它的信息。它可以通过`pip install networkx`在您的 Python 环境中安装。

# 如何做到这一点

此示例的脚本位于`08/06_visualizze_wikipedia_links.py`文件中。运行时，它会生成维基百科上初始 Python 页面上找到的链接的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/54f24aea-344a-42b8-b02b-a68c1a8287c4.png)链接的图表

现在我们可以看到页面之间的关系了！

# 工作原理

爬取从定义一级深度爬取开始：

```py
crawl_depth = 1 process = CrawlerProcess({
    'LOG_LEVEL': 'ERROR',
    'DEPTH_LIMIT': crawl_depth
})
process.crawl(WikipediaSpider)
spider = next(iter(process.crawlers)).spider
spider.max_items_per_page = 5 spider.max_crawl_depth = crawl_depth
process.start()

for pm in spider.linked_pages:
    print(pm.depth, pm.link, pm.child_link)
print("-"*80)
```

这些信息与之前的示例类似，现在我们需要将其转换为 NetworkX 可以用于图的模型。这始于创建一个 NetworkX 图模型：

```py
g = nx.Graph()
```

NetworkX 图由节点和边组成。从收集的数据中，我们必须创建一组唯一的节点（页面）和边（页面引用另一个页面的事实）。可以通过以下方式执行：

```py
nodes = {}
edges = {}

for pm in spider.linked_pages:
    if pm.title not in nodes:
        nodes[pm.title] = pm
        g.add_node(pm.title)

    if pm.child_title not in nodes:
        g.add_node(pm.child_title)

    link_key = pm.title + " ==> " + pm.child_title
    if link_key not in edges:
        edges[link_key] = link_key
        g.add_edge(pm.title, pm.child_title)
```

这通过遍历我们爬取的所有结果，并识别所有唯一节点（不同的页面），以及页面之间的所有链接。对于每个节点和边，我们使用 NetworkX 进行注册。

接下来，我们使用 Matplotlib 创建绘图，并告诉 NetworkX 如何在绘图中创建可视化效果：

```py
plt.figure(figsize=(10,8))

node_positions = nx.spring_layout(g)

nx.draw_networkx_nodes(g, node_positions, g.nodes, node_color='green', node_size=50)
nx.draw_networkx_edges(g, node_positions)

labels = { node: node for node in g.nodes() }
nx.draw_networkx_labels(g, node_positions, labels, font_size=9.5)

plt.show()
```

其中重要的部分首先是使用 NetworkX 在节点上形成弹簧布局。这计算出节点的实际位置，但不渲染节点或边。这是接下来的两行的目的，它们给出了 NetworkX 如何渲染节点和边的指令。最后，我们需要在节点上放置标签。

# 还有更多...

这次爬取只进行了一级深度的爬取。可以通过对代码进行以下更改来增加爬取的深度：

```py
crawl_depth = 2 process = CrawlerProcess({
    'LOG_LEVEL': 'ERROR',
    'DEPTH_LIMIT': crawl_depth
})
process.crawl(WikipediaSpider)
spider = next(iter(process.crawlers)).spider
spider.max_items_per_page = 5 spider.max_crawl_depth = crawl_depth
process.start()
```

基本上唯一的变化是增加一级深度。然后得到以下图表（任何弹簧图都会有随机性，因此实际结果会有不同的布局）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/6ddc2576-434d-411d-9d3f-15e9482e48f6.png)链接的蜘蛛图

这开始变得有趣，因为我们现在开始看到页面之间的相互关系和循环关系。

我敢你进一步增加深度和每页的链接数。

# 计算分离度

现在让我们计算任意两个页面之间的分离度。这回答了从源页面到另一个页面需要浏览多少页面的问题。这可能是一个非平凡的图遍历问题，因为两个页面之间可能有多条路径。幸运的是，对于我们来说，NetworkX 使用完全相同的图模型，具有内置函数来解决这个问题。

# 如何做到这一点

这个示例的脚本在`08/07_degrees_of_separation.py`中。代码与之前的示例相同，进行了 2 层深度的爬取，只是省略了图表，并要求 NetworkX 解决`Python_(programming_language)`和`Dennis_Ritchie`之间的分离度：

```py
Degrees of separation: 1
 Python_(programming_language)
   C_(programming_language)
    Dennis_Ritchie
```

这告诉我们，要从`Python_(programming_language)`到`Dennis_Ritchie`，我们必须通过另一个页面：`C_(programming_language)`。因此，一度分离。如果我们直接到`C_(programming_language)`，那么就是 0 度分离。

# 它是如何工作的

这个问题的解决方案是由一种称为**A***的算法解决的。**A***算法确定图中两个节点之间的最短路径。请注意，这条路径可以是不同长度的多条路径，正确的结果是最短路径。对我们来说好消息是，NetworkX 有一个内置函数来为我们做这个。它可以用一条简单的语句完成：

```py
path = nx.astar_path(g, "Python_(programming_language)", "Dennis_Ritchie")
```

从这里我们报告实际路径：

```py
degrees_of_separation = int((len(path) - 1) / 2)
print("Degrees of separation: {}".format(degrees_of_separation))
for i in range(0, len(path)):
    print(" " * i, path[i])
```

# 还有更多...

有关**A***算法的更多信息，请查看[此页面](https://en.wikipedia.org/wiki/A*_search_algorithm)。


# 第九章：创建一个简单的数据 API

在本章中，我们将涵盖：

+   使用 Flask-RESTful 创建 REST API

+   将 REST API 与抓取代码集成

+   添加一个用于查找工作列表技能的 API

+   将数据存储在 Elasticsearch 中作为抓取请求的结果

+   在抓取之前检查 Elasticsearch 中的列表

# 介绍

我们现在已经达到了学习抓取的一个激动人心的转折点。从现在开始，我们将学习使用几个 API、微服务和容器工具将抓取器作为服务运行，所有这些都将允许在本地或云中运行抓取器，并通过标准化的 REST API 访问抓取器。

我们将在本章中开始这个新的旅程，使用 Flask-RESTful 创建一个简单的 REST API，最终我们将使用它来对服务进行页面抓取请求。我们将把这个 API 连接到一个 Python 模块中实现的抓取器功能，该模块重用了在第七章中讨论的从 StackOverflow 工作中抓取的概念，*文本整理和分析*。

最后几个食谱将重点介绍将 Elasticsearch 用作这些结果的缓存，存储我们从抓取器中检索的文档，然后首先在缓存中查找它们。我们将在第十一章中进一步研究 ElasticCache 的更复杂用法，比如使用给定技能集进行工作搜索，*使抓取器成为真正的服务*。

# 使用 Flask-RESTful 创建 REST API

我们从使用 Flask-RESTful 创建一个简单的 REST API 开始。这个初始 API 将由一个单一的方法组成，让调用者传递一个整数值，并返回一个 JSON 块。在这个食谱中，参数及其值以及返回值在这个时候并不重要，因为我们首先要简单地使用 Flask-RESTful 来运行一个 API。

# 准备工作

Flask 是一个 Web 微框架，可以让创建简单的 Web 应用功能变得非常容易。Flask-RESTful 是 Flask 的一个扩展，可以让创建 REST API 同样简单。您可以在`flask.pocoo.org`上获取 Flask 并了解更多信息。Flask-RESTful 可以在`https://flask-restful.readthedocs.io/en/latest/`上了解。可以使用`pip install flask`将 Flask 安装到您的 Python 环境中。Flask-RESTful 也可以使用`pip install flask-restful`进行安装。

本书中其余的食谱将在章节目录的子文件夹中。这是因为这些食谱中的大多数要么需要多个文件来操作，要么使用相同的文件名（即：`apy.py`）。

# 如何做

初始 API 实现在`09/01/api.py`中。API 本身和 API 的逻辑都在这个单一文件`api.py`中实现。API 可以以两种方式运行，第一种方式是简单地将文件作为 Python 脚本执行。

然后可以使用以下命令启动 API：

```py
python api.py
```

运行时，您将首先看到类似以下的输出：

```py
Starting the job listing API
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
 * Restarting with stat
Starting the job listing API
 * Debugger is active!
 * Debugger pin code: 362-310-034
```

该程序在`127.0.0.1:5000`上公开了一个 REST API，我们可以使用`GET`请求到路径`/joblisting/<joblistingid>`来请求工作列表。我们可以使用 curl 尝试一下：

```py
curl localhost:5000/joblisting/1
```

此命令的结果将如下：

```py
{
 "YouRequestedJobWithId": "1"
}
```

就像这样，我们有一个正在运行的 REST API。现在让我们看看它是如何实现的。

# 它是如何工作的

实际上并没有太多的代码，这就是 Flask-RESTful 的美妙之处。代码以导入`flask`和`flask_restful`开始。

```py
from flask import Flask
from flask_restful import Resource, Api
```

接下来是用于设置 Flask-RESTful 的初始配置的代码：

```py
app = Flask(__name__)
api = Api(app)
```

接下来是一个代表我们 API 实现的类的定义：

```py
class JobListing(Resource):
    def get(self, job_listing_id):
        print("Request for job listing with id: " + job_listing_id)
        return {'YouRequestedJobWithId': job_listing_id}
```

Flask-RESTful 将映射 HTTP 请求到这个类的方法。具体来说，按照惯例，`GET`请求将映射到名为`get`的成员函数。将 URL 的值映射到函数的`jobListingId`参数。然后，该函数返回一个 Python 字典，Flask-RESTful 将其转换为 JSON。

下一行代码告诉 Flask-RESTful 如何将 URL 的部分映射到我们的类：

```py
api.add_resource(JobListing, '/', '/joblisting/<string:job_listing_id>')
```

这定义了以`/joblisting`开头的路径的 URL 将映射到我们的`JobListing`类，并且 URL 的下一部分表示要传递给`get`方法的`jobListingId`参数的字符串。由于在此映射中未定义其他动词，因此假定使用 GET HTTP 动词。

最后，我们有一段代码，指定了当文件作为脚本运行时，我们只需执行`app.run()`（在这种情况下传递一个参数以便获得调试输出）。

```py
if __name__ == '__main__':
    print("Starting the job listing API")
    app.run(debug=True)
```

然后，Flask-RESTful 找到我们的类并设置映射，开始在`127.0.0.1:5000`（默认值）上监听，并将请求转发到我们的类和方法。

# 还有更多...

Flask-RESTful 的默认运行端口是`5000`。可以使用`app.run()`的替代形式来更改。对于我们的食谱，将其保留在 5000 上就可以了。最终，您会在类似容器的东西中运行此服务，并在前面使用诸如 NGINX 之类的反向代理，并执行公共端口映射到内部服务端口。

# 将 REST API 与抓取代码集成

在这个食谱中，我们将把我们为从 StackOverflow 获取干净的工作列表编写的代码与我们的 API 集成。这将导致一个可重用的 API，可以用来执行按需抓取，而客户端无需了解抓取过程。基本上，我们将创建一个*作为服务的抓取器*，这是我们在本书的其余食谱中将花费大量时间的概念。

# 准备工作

这个过程的第一部分是将我们在第七章中编写的现有代码创建为一个模块，以便我们可以重用它。我们将在本书的其余部分中的几个食谱中重用这段代码。在将其与 API 集成之前，让我们简要地检查一下这个模块的结构和内容。

该模块的代码位于项目的模块文件夹中的`sojobs`（用于 StackOverflow 职位）模块中。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/c192716d-ac40-476d-936a-36091d78b2fb.png)sojobs 文件夹

在大多数情况下，这些文件是从第七章中使用的文件复制而来，即*文本整理和分析*。可重用的主要文件是`scraping.py`，其中包含几个函数，用于方便抓取。在这个食谱中，我们将使用的函数是`get_job_listing_info`：

```py
def get_job_listing(job_listing_id):
    print("Got a request for a job listing with id: " + job_listing_id)

    req = requests.get("https://stackoverflow.com/jobs/" + job_listing_id)
    content = req.text

    bs = BeautifulSoup(content, "lxml")
    script_tag = bs.find("script", {"type": "application/ld+json"})

    job_listing_contents = json.loads(script_tag.contents[0])
    desc_bs = BeautifulSoup(job_listing_contents["description"], "lxml")
    just_text = desc_bs.find_all(text=True)

    joined = ' '.join(just_text)
    tokens = word_tokenize(joined)

    stop_list = stopwords.words('english')
    with_no_stops = [word for word in tokens if word.lower() not in stop_list]
    two_grammed = tech_2grams(with_no_stops)
    cleaned = remove_punctuation(two_grammed)

    result = {
        "ID": job_listing_id,
        "JSON": job_listing_contents,
        "TextOnly": just_text,
        "CleanedWords": cleaned
    }

    return json.dumps(result)
```

回到第七章中的代码，您可以看到这段代码是我们在那些食谱中创建的重用代码。不同之处在于，这个函数不是读取单个本地的`.html`文件，而是传递了一个工作列表的标识符，然后构造了该工作列表的 URL，使用 requests 读取内容，执行了几项分析，然后返回结果。

请注意，该函数返回一个 Python 字典，其中包含请求的工作 ID、原始 HTML、列表的文本和清理后的单词列表。该 API 将这些结果聚合返回给调用者，其中包括`ID`，因此很容易知道请求的工作，以及我们执行各种清理的所有其他结果。因此，我们已经创建了一个增值服务，用于工作列表，而不仅仅是获取原始 HTML。

确保你的 PYTHONPATH 环境变量指向模块目录，或者你已经设置好你的 Python IDE 以在这个目录中找到模块。否则，你将会得到找不到这个模块的错误。

# 如何做

我们按以下步骤进行食谱：

1.  这个食谱的 API 代码在`09/02/api.py`中。这扩展了上一个食谱中的代码，以调用`sojobs`模块中的这个函数。服务的代码如下：

```py
from flask import Flask
from flask_restful import Resource, Api
from sojobs.scraping import get_job_listing_info

app = Flask(__name__)
api = Api(app)

class JobListing(Resource):
    def get(self, job_listing_id):
        print("Request for job listing with id: " + job_listing_id)
        listing = get_job_listing_info(job_listing_id)
        print("Got the following listing as a response: " + listing)
        return listing

api.add_resource(JobListing, '/', '/joblisting/<string:job_listing_id>')

if __name__ == '__main__':
    print("Starting the job listing API")
    app.run(debug=True)
```

请注意，主要的区别是从模块导入函数，并调用函数并从结果返回数据。

1.  通过执行带有 Python `api.py`的脚本来运行服务。然后我们可以使用`curl`测试 API。以下请求我们之前检查过的 SpaceX 工作列表。

```py
curl localhost:5000/joblisting/122517
```

1.  这导致了相当多的输出。以下是部分响应的开头：

```py
"{\"ID\": \"122517\", \"JSON\": {\"@context\": \"http://schema.org\", \"@type\": \"JobPosting\", \"title\": \"SpaceX Enterprise Software Engineer, Full Stack\", \"skills\": [\"c#\", \"sql\", \"javascript\", \"asp.net\", \"angularjs\"], \"description\": \"<h2>About this job</h2>\\r\\n<p><span>Location options: <strong>Paid relocation</strong></span><br/><span>Job type: <strong>Permanent</strong></span><br/><span>Experience level: <strong>Mid-Level, Senior</strong></span><br/><span>Role: <strong>Full Stack Developer</strong></span><br/><span>Industry: <strong>Aerospace, Information Technology, Web Development</strong></span><br/><span>Company size: <strong>1k-5k people</strong></span><br/><span>Company type: <strong>Private</strong></span><br/></p><br/><br/><h2>Technologies</h2> <p>c#, sql, javascr
```

# 添加一个 API 来查找工作列表的技能

在这个食谱中，我们向我们的 API 添加了一个额外的操作，允许我们请求与工作列表相关的技能。这演示了一种能够检索数据的子集而不是整个列表内容的方法。虽然我们只对技能做了这个操作，但这个概念可以很容易地扩展到任何其他数据的子集，比如工作的位置、标题，或者几乎任何对 API 用户有意义的其他内容。

# 准备工作

我们要做的第一件事是向`sojobs`模块添加一个爬取函数。这个函数将被命名为`get_job_listing_skills`。以下是这个函数的代码：

```py
def get_job_listing_skills(job_listing_id):
    print("Got a request for a job listing skills with id: " + job_listing_id)

    req = requests.get("https://stackoverflow.com/jobs/" + job_listing_id)
    content = req.text

    bs = BeautifulSoup(content, "lxml")
    script_tag = bs.find("script", {"type": "application/ld+json"})

    job_listing_contents = json.loads(script_tag.contents[0])
    skills = job_listing_contents['skills']

    return json.dumps(skills)
```

这个函数检索工作列表，提取 StackOverflow 提供的 JSON，然后只返回 JSON 的`skills`属性。

现在，让我们看看如何添加一个方法来调用 REST API。

# 如何做

我们按以下步骤进行食谱：

1.  这个食谱的 API 代码在`09/03/api.py`中。这个脚本添加了一个额外的类`JobListingSkills`，具体实现如下：

```py
class JobListingSkills(Resource):
    def get(self, job_listing_id):
        print("Request for job listing's skills with id: " + job_listing_id)
        skills = get_job_listing_skills(job_listing_id)
        print("Got the following skills as a response: " + skills)
        return skills
```

这个实现与上一个食谱类似，只是调用了获取技能的新函数。

1.  我们仍然需要添加一个语句来告诉 Flask-RESTful 如何将 URL 映射到这个类的`get`方法。因为我们实际上是在检索整个工作列表的子属性，我们将扩展我们的 URL 方案，包括一个额外的段代表整体工作列表资源的子属性。

```py
api.add_resource(JobListingSkills, '/', '/joblisting/<string:job_listing_id>/skills')
```

1.  现在我们可以使用以下 curl 仅检索技能：

```py
curl localhost:5000/joblisting/122517/skills
```

这给我们带来了以下结果：

```py
"[\"c#\", \"sql\", \"javascript\", \"asp.net\", \"angularjs\"]"
```

# 将数据存储在 Elasticsearch 中作为爬取请求的结果

在这个食谱中，我们扩展了我们的 API，将我们从爬虫那里收到的数据保存到 Elasticsearch 中。我们稍后会使用这个（在下一个食谱中）来通过使用 Elasticsearch 中的内容来优化请求，以便我们不会重复爬取已经爬取过的工作列表。因此，我们可以与 StackOverflow 的服务器友好相处。

# 准备工作

确保你的 Elasticsearch 在本地运行，因为代码将访问`localhost:9200`上的 Elasticsearch。有一个很好的快速入门可用于 [`www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html)，或者你可以在 第十章 中查看 Docker Elasticsearch 食谱，*使用 Docker 创建爬虫微服务*，如果你想在 Docker 中运行它。

安装后，你可以使用以下`curl`检查正确的安装：

```py
curl 127.0.0.1:9200?pretty
```

如果安装正确，你将得到类似以下的输出：

```py
{
 "name": "KHhxNlz",
 "cluster_name": "elasticsearch",
 "cluster_uuid": "fA1qyp78TB623C8IKXgT4g",
 "version": {
 "number": "6.1.1",
 "build_hash": "bd92e7f",
 "build_date": "2017-12-17T20:23:25.338Z",
 "build_snapshot": false,
 "lucene_version": "7.1.0",
 "minimum_wire_compatibility_version": "5.6.0",
 "minimum_index_compatibility_version": "5.0.0"
 },
 "tagline": "You Know, for Search"
}
```

您还需要安装 elasticsearch-py。它可以在[`www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html`](https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/index.html)找到，但可以使用`pip install elasticsearch`快速安装。

# 如何做到的

我们将对我们的 API 代码进行一些小的更改。之前的代码已经复制到`09/04/api.py`中，并进行了一些修改。

1.  首先，我们为 elasticsearch-py 添加了一个导入：

```py
from elasticsearch import Elasticsearch
```

1.  现在我们对`JobListing`类的`get`方法进行了快速修改（我在 JobListingSkills 中也做了同样的修改，但出于简洁起见，这里省略了）：

```py
class JobListing(Resource):
    def get(self, job_listing_id):
        print("Request for job listing with id: " + job_listing_id)
        listing = get_job_listing_info(job_listing_id)

        es = Elasticsearch()
        es.index(index='joblistings', doc_type='job-listing', id=job_listing_id, body=listing)

        print("Got the following listing as a response: " + listing)
        return listing
```

1.  这两行新代码创建了一个`Elasticsearch`对象，然后将结果文档插入到 ElasticSearch 中。在第一次调用 API 之前，我们可以通过以下 curl 看到没有内容，也没有`'joblistings'`索引：

```py
curl localhost:9200/joblistings
```

1.  考虑到我们刚刚安装了 Elasticsearch，这将导致以下错误。

```py
{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index","resource.type":"index_or_alias","resource.id":"joblistings","index_uuid":"_na_","index":"joblistings"}],"type":"index_not_found_exception","reason":"no such index","resource.type":"index_or_alias","resource.id":"joblistings","index_uuid":"_na_","index":"joblistings"},"status":404}
```

1.  现在通过`python api.py`启动 API。然后发出`curl`以获取作业列表（`curl localhost:5000/joblisting/122517`）。这将导致类似于之前的配方的输出。现在的区别是这个文档将存储在 Elasticsearch 中。

1.  现在重新发出先前的 curl 以获取索引：

```py
curl localhost:9200/joblistings
```

1.  现在你会得到以下结果（只显示前几行）：

```py
{
 "joblistings": {
  "aliases": {},
  "mappings": {
   "job-listing": {
     "properties": {
       "CleanedWords" {
         "type": "text",
         "fields": {
           "keyword": {
           "type": "keyword",
           "ignore_above": 256
          }
        }
       },
     "ID": {
       "type": "text",
       "fields": {
         "keyword": {
         "type": "keyword",
         "ignore_above": 256
        }
      }
    },
```

已经创建了一个名为`joblistings`的索引，这个结果展示了 Elasticsearch 通过检查文档识别出的索引结构。

虽然 Elasticsearch 是无模式的，但它会检查提交的文档并根据所找到的内容构建索引。

1.  我们刚刚存储的特定文档可以通过以下 curl 检索：

```py
curl localhost:9200/joblistings/job-listing/122517
```

1.  这将给我们以下结果（同样，只显示内容的开头）：

```py
{
 "_index": "joblistings",
 "_type": "job-listing",
 "_id": "122517",
 "_version": 1,
 "found": true,
 "_source": {
  "ID": "122517",
  "JSON": {
   "@context": "http://schema.org",
   "@type": "JobPosting",
   "title": "SpaceX Enterprise Software Engineer, Full Stack",
   "skills": [
    "c#",
    "sql",
    "javascript",
    "asp.net",
    "angularjs"
  ],
  "description": "<h2>About this job</h2>\r\n<p><span>Location options: <strong>Paid relocation</strong></span><br/><span>Job type: <strong>Permanent</strong></span><br/><span>Experience level: <strong>Mid-Level,
```

就像这样，只用两行代码，我们就将文档存储在了 Elasticsearch 数据库中。现在让我们简要地看一下这是如何工作的。

# 它是如何工作的

使用以下行执行了文档的存储：

```py
es.index(index='joblistings', doc_type='job-listing', id=job_listing_id, body=listing)
```

让我们检查每个参数相对于存储这个文档的作用。

`index`参数指定我们要将文档存储在其中的 Elasticsearch 索引。它的名称是`joblistings`。这也成为用于检索文档的 URL 的第一部分。

每个 Elasticsearch 索引也可以有多个文档“类型”，这些类型是逻辑上的文档集合，可以表示索引内不同类型的文档。我们使用了`'job-listing'`，这个值也构成了用于检索特定文档的 URL 的第二部分。

Elasticsearch 不要求为每个文档指定标识符，但如果我们提供一个，我们可以查找特定的文档而不必进行搜索。我们将使用文档 ID 作为作业列表 ID。

最后一个参数`body`指定文档的实际内容。这段代码只是传递了从爬虫接收到的结果。

# 还有更多...

让我们简要地看一下 Elasticsearch 通过查看文档检索的结果为我们做了什么。

首先，我们可以在结果的前几行看到索引、文档类型和 ID：

```py
{
 "_index": "joblistings",
 "_type": "job-listing",
 "_id": "122517",
```

当使用这三个值进行查询时，文档的检索非常高效。

每个文档也存储了一个版本，这种情况下是 1。

```py
    "_version": 1,
```

如果我们使用相同的代码进行相同的查询，那么这个文档将再次存储，具有相同的索引、文档类型和 ID，因此版本将增加。相信我，再次对 API 进行 curl，你会看到这个版本增加到 2。

现在检查``"JSON"``属性的前几个属性的内容。我们将 API 返回的结果的此属性分配为嵌入在 HTML 中的 StackOverflow 作业描述的 JSON。

```py
 "JSON": {
  "@context": "http://schema.org",
  "@type": "JobPosting",
  "title": "SpaceX Enterprise Software Engineer, Full Stack",
  "skills": [
   "c#",
   "sql",
   "javascript",
   "asp.net",
   "angularjs"
  ],
```

这就是像 StackOverflow 这样的网站给我们提供结构化数据的美妙之处，使用 Elasticsearch 等工具，我们可以得到结构良好的数据。我们可以并且将利用这一点，只需很少量的代码就可以产生很大的效果。我们可以轻松地使用 Elasticsearch 执行查询，以识别基于特定技能（我们将在即将到来的示例中执行此操作）、行业、工作福利和其他属性的工作列表。

我们的 API 的结果还返回了一个名为`CleanedWords`的属性，这是我们的几个 NLP 过程提取高价值词语和术语的结果。以下是最终存储在 Elasticsearch 中的值的摘录：

```py
 "CleanedWords": [
  "job",
  "Location",
  "options",
  "Paid relocation",
  "Job",
  "type",
  "Permanent",
  "Experience",
  "level",
```

而且，我们将能够使用这些来执行丰富的查询，帮助我们根据这些特定词语找到特定的匹配项。

# 在爬取之前检查 Elasticsearch 中是否存在列表

现在让我们通过检查是否已经存储了工作列表来利用 Elasticsearch 作为缓存，因此不需要再次访问 StackOverflow。我们扩展 API 以执行对工作列表的爬取，首先搜索 Elasticsearch，如果结果在那里找到，我们返回该数据。因此，我们通过将 Elasticsearch 作为工作列表缓存来优化这个过程。

# 如何做

我们按照以下步骤进行：

这个示例的代码在`09/05/api.py`中。`JobListing`类现在有以下实现：

```py
class JobListing(Resource):
    def get(self, job_listing_id):
        print("Request for job listing with id: " + job_listing_id)

        es = Elasticsearch()
        if (es.exists(index='joblistings', doc_type='job-listing', id=job_listing_id)):
            print('Found the document in ElasticSearch')
            doc =  es.get(index='joblistings', doc_type='job-listing', id=job_listing_id)
            return doc['_source']

        listing = get_job_listing_info(job_listing_id)
        es.index(index='joblistings', doc_type='job-listing', id=job_listing_id, body=listing)

        print("Got the following listing as a response: " + listing)
        return listing
```

在调用爬虫代码之前，API 会检查文档是否已经存在于 Elasticsearch 中。这是通过名为`exists`的方法执行的，我们将要获取的索引、文档类型和 ID 传递给它。

如果返回 true，则使用 Elasticsearch 对象的`get`方法检索文档，该方法也具有相同的参数。这将返回一个表示 Elasticsearch 文档的 Python 字典，而不是我们存储的实际数据。实际的数据/文档是通过访问字典的`'_source'`键来引用的。

# 还有更多...

`JobListingSkills` API 实现遵循了稍微不同的模式。以下是它的代码：

```py
class JobListingSkills(Resource):
    def get(self, job_listing_id):
        print("Request for job listing's skills with id: " + job_listing_id)

        es = Elasticsearch()
        if (es.exists(index='joblistings', doc_type='job-listing', id=job_listing_id)):
            print('Found the document in ElasticSearch')
            doc =  es.get(index='joblistings', doc_type='job-listing', id=job_listing_id)
            return doc['_source']['JSON']['skills']

        skills = get_job_listing_skills(job_listing_id)

        print("Got the following skills as a response: " + skills)
        return skills
```

这个实现仅在检查文档是否已经存在于 ElasticSearch 时使用 ElasticSearch。它不会尝试保存从爬虫中新检索到的文档。这是因为`get_job_listing`爬虫的结果只是技能列表，而不是整个文档。因此，这个实现可以使用缓存，但不会添加新数据。这是设计决策之一，即对爬取方法进行不同的设计，返回的只是被爬取文档的子集。

对此的一个潜在解决方案是，将这个 API 方法调用`get_job_listing_info`，然后保存文档，最后只返回特定的子集（在这种情况下是技能）。再次强调，这最终是围绕 sojobs 模块的用户需要哪些类型的方法的设计考虑。出于这些初始示例的目的，考虑到在该级别有两个不同的函数返回不同的数据集更好。


# 第十章：使用 Docker 创建爬虫微服务

在本章中，我们将涵盖：

+   安装 Docker

+   从 Docker Hub 安装 RabbitMQ 容器

+   运行一个 Docker 容器（RabbitMQ）

+   停止和删除容器和镜像

+   创建一个 API 容器

+   使用 Nameko 创建一个通用微服务

+   创建一个爬取微服务

+   创建一个爬虫容器

+   创建后端（ElasticCache）容器

+   使用 Docker Compose 组合和运行爬虫容器

# 介绍

在本章中，我们将学习如何将我们的爬虫容器化，使其准备好进入现实世界，开始为真正的、现代的、云启用的操作打包。这将涉及将爬虫的不同元素（API、爬虫、后端存储）打包为可以在本地或云中运行的 Docker 容器。我们还将研究将爬虫实现为可以独立扩展的微服务。

我们将主要关注使用 Docker 来创建我们的容器化爬虫。Docker 为我们提供了一种方便和简单的方式，将爬虫的各个组件（API、爬虫本身以及其他后端，如 Elasticsearch 和 RabbitMQ）打包为一个服务。通过使用 Docker 对这些组件进行容器化，我们可以轻松地在本地运行容器，编排组成服务的不同容器，还可以方便地发布到 Docker Hub。然后我们可以轻松地部署它们到云提供商，以在云中创建我们的爬虫。

关于 Docker（以及容器一般）的一大好处是，我们既可以轻松地安装预打包的容器，而不必费力地获取应用程序的安装程序并处理所有配置的麻烦。我们还可以将我们编写的软件打包到一个容器中，并在不必处理所有这些细节的情况下运行该容器。此外，我们还可以发布到私有或公共存储库以分享我们的软件。

Docker 真正伟大的地方在于容器在很大程度上是平台无关的。任何基于 Linux 的容器都可以在任何操作系统上运行，包括 Windows（它在虚拟化 Linux 时使用 VirtualBox，并且对 Windows 用户来说基本上是透明的）。因此，一个好处是任何基于 Linux 的 Docker 容器都可以在任何 Docker 支持的操作系统上运行。不再需要为应用程序创建多个操作系统版本了！

让我们学习一些 Docker 知识，并将我们的爬虫组件放入容器中。

# 安装 Docker

在这个教程中，我们将学习如何安装 Docker 并验证其是否正在运行。

# 准备工作

Docker 支持 Linux、macOS 和 Windows，因此它覆盖了主要平台。Docker 的安装过程因您使用的操作系统而异，甚至在不同的 Linux 发行版之间也有所不同。

Docker 网站对安装过程有很好的文档，因此本教程将快速浏览 macOS 上安装的重要要点。安装完成后，至少从 CLI 方面来看，Docker 的用户体验是相同的。

参考文献，Docker 的安装说明主页位于：[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)

# 如何做

我们将按照以下步骤进行：

1.  我们将使用一个名为 Docker 社区版的 Docker 变体，并在 macOS 上进行安装。在 macOS 的下载页面上，您将看到以下部分。点击稳定频道的下载，除非您感到勇敢并想使用 Edge 频道。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/3fe42443-f9f8-4dc5-8679-221293a203fa.png)Docker 下载页面

1.  这将下载一个`Docker.dmg`文件。打开 DMG，您将看到以下窗口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/b2a7044a-5f06-4874-96c6-112496770357.png)Docker for Mac 安装程序窗口

1.  将*Moby*鲸鱼拖到您的应用程序文件夹中。然后打开`Docker.app`。您将被要求验证安装，因此输入密码，安装将完成。完成后，您将在状态栏中看到 Moby：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/db37ccda-6c94-44dd-b327-f943fe3afbdb.png)Moby 工具栏图标

1.  点击 Moby 可以获得许多配置设置、状态和信息。我们将主要使用命令行工具。要验证命令行是否正常工作，请打开终端并输入命令 docker info。Docker 将为您提供有关其配置和状态的一些信息。

# 从 Docker Hub 安装 RabbitMQ 容器

可以从许多容器存储库获取预构建的容器。Docker 预先配置了与 Docker Hub 的连接，许多软件供应商和爱好者在那里发布一个或多个配置的容器。

在这个教程中，我们将安装 RabbitMQ，这将被我们在另一个教程中使用的另一个工具 Nameko 所使用，以作为我们的抓取微服务的消息总线。

# 准备工作

通常，安装 RabbitMQ 是一个相当简单的过程，但它确实需要几个安装程序：一个用于 Erlang，然后一个用于 RabbitMQ 本身。如果需要管理工具，比如基于 Web 的管理 GUI，那就是另一步（尽管是一个相当小的步骤）。通过使用 Docker，我们可以简单地获取所有这些预配置的容器。让我们去做吧。

# 如何做

我们按照以下步骤进行教程：

1.  可以使用`docker pull`命令获取容器。此命令将检查并查看本地是否已安装容器，如果没有，则为我们获取。从命令行尝试该命令，包括`--help`标志。您将得到以下信息，告诉您至少需要一个参数：容器的名称和可能的标签：

```py
$ docker pull --help

Usage: docker pull [OPTIONS] NAME[:TAG|@DIGEST]

Pull an image or a repository from a registry

Options:
  -a, --all-tags Download all tagged images in the repository
      --disable-content-trust Skip image verification (default true)
      --help Print usage
```

1.  我们将拉取`rabbitmq:3-management`容器。冒号前的部分是容器名称，第二部分是标签。标签通常代表容器的版本或特定配置。在这种情况下，我们希望获取带有 3-management 标签的 RabbitMQ 容器。这个标签意味着我们想要带有 RabbitMQ 版本 3 和管理工具安装的容器版本。

在我们这样做之前，您可能会想知道这是从哪里来的。它来自 Docker Hub（`hub.docker.com`），来自 RabbitMQ 存储库。该存储库的页面位于[`hub.docker.com/_/rabbitmq/`](https://hub.docker.com/_/rabbitmq/)，并且看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/2210e62e-0f9d-4a21-b71c-41c37d0dd8c6.png)RabbitMQ 存储库页面请注意显示标签的部分，以及它具有 3-management 标签。如果您向下滚动，还会看到有关容器和标签的更多信息，以及它们的组成。

1.  现在让我们拉取这个容器。从终端发出以下命令：

```py
$docker pull rabbitmq:3-management
```

1.  Docker 将访问 Docker Hub 并开始下载。您将在类似以下的输出中看到这一过程，这可能会根据您的下载速度运行几分钟：

```py
3-management: Pulling from library/rabbitmq
e7bb522d92ff: Pull complete 
ad90649c4d84: Pull complete 
5a318b914d6c: Pull complete 
cedd60f70052: Pull complete 
f4ec28761801: Pull complete 
b8fa44aa9074: Pull complete 
e3b16d5314a0: Pull complete 
7d93dd9659c8: Pull complete 
356c2fc6e036: Pull complete 
3f52408394ed: Pull complete 
7c89a0fb0219: Pull complete 
1e37a15bd7aa: Pull complete 
9313c22c63d5: Pull complete 
c21bcdaa555d: Pull complete 
Digest: sha256:c7466443efc28846bb0829d0f212c1c32e2b03409996cee38be4402726c56a26 
Status: Downloaded newer image for rabbitmq:3-management 
```

恭喜！如果这是您第一次使用 Docker，您已经下载了您的第一个容器镜像。您可以使用 docker images 命令验证它是否已下载和安装。

```py
$ docker images 
REPOSITORY TAG IMAGE    ID           CREATED     SIZE 
rabbitmq   3-management 6cb6e2f951a8 10 days ago 151MB
```

# 运行 Docker 容器（RabbitMQ）

在这个教程中，我们将学习如何运行 docker 镜像，从而创建一个容器。

# 准备工作

我们将启动我们在上一个教程中下载的 RabbitMQ 容器镜像。这个过程代表了许多容器的运行方式，因此它是一个很好的例子。

# 如何做

我们按照以下步骤进行教程：

1.  到目前为止，我们已经下载了一个可以运行以创建实际容器的镜像。容器是使用特定参数实例化的镜像，这些参数需要配置容器中的软件。我们通过运行 docker run 并传递镜像名称/标签以及运行镜像所需的任何其他参数来运行容器（这些参数特定于镜像，通常可以在 Docker Hub 页面上找到镜像的参数）。

我们需要使用以下特定命令来运行 RabbitMQ 使用此镜像：

```py
$ docker run -d -p 15672:15672 -p 5672:5672 rabbitmq:3-management
094a138383764f487e5ad0dab45ff64c08fe8019e5b0da79cfb1c36abec69cc8
```

1.  `docker run`告诉 Docker 在容器中运行一个镜像。我们要运行的镜像在语句的末尾：`rabbitmq:3-management`。`-d`选项告诉 Docker 以分离模式运行容器，这意味着容器的输出不会路由到终端。这允许我们保留对终端的控制。`-p`选项将主机端口映射到容器端口。RabbitMQ 使用 5672 端口进行实际命令，15672 端口用于 Web UI。这将在您的实际操作系统上的相同端口映射到容器中运行的软件使用的端口。

大的十六进制值输出是容器的标识符。第一部分，094a13838376，是 Docker 创建的容器 ID（对于每个启动的容器都会有所不同）。

1.  我们可以使用 docker ps 来检查正在运行的容器，这会给我们每个容器的进程状态：

```py
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
094a13838376 rabbitmq:3-management "docker-entrypoint..." 5 minutes ago Up 5 minutes 4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp dreamy_easley
```

我们可以看到容器 ID 和其他信息，例如它基于哪个镜像，它已经运行了多长时间，容器暴露了哪些端口，我们定义的端口映射，以及 Docker 为我们创建的友好名称，以便我们引用容器。

1.  检查是否正在运行的真正方法是打开浏览器，导航到`localhost:15672`，即 RabbitMQ 管理 UI 的 URL：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/d8715fbc-5686-48c9-9f38-16e8c54aa325.png)RabbitMQ 管理 UI 登录页面

1.  该容器的默认用户名和密码是 guest:guest。输入这些值，您将看到管理 UI：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/20179fcc-8e5c-467f-8421-49f1dd7b3e9c.png)管理 UI

# 还有更多...

这实际上是我们将在 RabbitMQ 中取得的进展。在以后的教程中，我们将使用 Nameko Python 微服务框架，它将在我们不知情的情况下透明地使用 RabbitMQ。我们首先需要确保它已安装并正在运行。

# 创建和运行 Elasticsearch 容器

当我们正在查看拉取容器镜像和启动容器时，让我们去运行一个 Elasticsearch 容器。

# 如何做

像大多数 Docker 一样，有很多不同版本的 Elasticsearch 容器可用。我们将使用 Elastic 自己的 Docker 存储库中提供的官方 Elasticsearch 镜像：

1.  要安装镜像，请输入以下内容：

```py
$docker pull docker.elastic.co/elasticsearch/elasticsearch:6.1.1
```

请注意，我们正在使用另一种指定要拉取的镜像的方式。由于这是在 Elastic 的 Docker 存储库上，我们包括了包含容器镜像 URL 的限定名称，而不仅仅是镜像名称。 :6.1.1 是标签，指定了该镜像的特定版本。

1.  在处理此过程时，您将看到一些输出，显示下载过程。完成后，您将看到几行让您知道已完成：

```py
Digest: sha256:9e6c7d3c370a17736c67b2ac503751702e35a1336724741d00ed9b3d00434fcb 
Status: Downloaded newer image for docker.elastic.co/elasticsearch/elasticsearch:6.1.1
```

1.  现在让我们检查 Docker 中是否有可用的镜像：

```py
$ docker images 
REPOSITORY TAG IMAGE ID CREATED SIZE 
rabbitmq 3-management 6cb6e2f951a8 12 days ago 151MB docker.elastic.co/elasticsearch/elasticsearch 6.1.1 06f0d8328d66 2 weeks ago 539MB
```

1.  现在我们可以使用以下 Docker 命令运行 Elasticsearch：

```py
docker run -e ELASTIC_PASSWORD=MagicWord -p 9200:9200 -p 9300:9300 docker.elastic.co/elasticsearch/elasticsearch:6.1.1
```

1.  环境变量`ELASTIC_PASSWORD`传递密码，两个端口将主机端口映射到容器中暴露的 Elasticsearch 端口。

1.  接下来，检查容器是否在 Docker 中运行：

```py
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
308a02f0e1a5 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 7 seconds ago Up 6 seconds 0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp romantic_kowalevski
094a13838376 rabbitmq:3-management "docker-entrypoint..." 47 hours ago Up 47 hours 4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp dreamy_easley
```

1.  最后，执行以下 curl。如果 Elasticsearch 正在运行，您将收到`You Know, for Search`消息：

```py
$ curl localhost:9200
{
 "name" : "8LaZfMY",
 "cluster_name" : "docker-cluster",
 "cluster_uuid" : "CFgPERC8TMm5KaBAvuumvg",
 "version" : {
 "number" : "6.1.1",
 "build_hash" : "bd92e7f",
 "build_date" : "2017-12-17T20:23:25.338Z",
 "build_snapshot" : false,
 "lucene_version" : "7.1.0",
 "minimum_wire_compatibility_version" : "5.6.0",
 "minimum_index_compatibility_version" : "5.0.0"
 },
 "tagline" : "You Know, for Search"
}
```

# 停止/重新启动容器并删除镜像

让我们看看如何停止和删除一个容器，然后也删除它的镜像。

# 如何做

我们按照以下步骤进行：

1.  首先查询正在运行的 Docker 容器：

```py
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
308a02f0e1a5 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 7 seconds ago Up 6 seconds 0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp romantic_kowalevski
094a13838376 rabbitmq:3-management "docker-entrypoint..." 47 hours ago Up 47 hours 4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp dreamy_easley
```

1.  让我们停止 Elasticsearch 容器。要停止一个容器，我们使用`docker stop <container-id>`。Elasticsearch 的容器 ID 是`308a02f0e1a5`。以下停止容器

```py
$ docker stop 30
30
```

为了确认容器已停止，Docker 将回显您告诉它停止的容器 ID

请注意，我不必输入完整的容器 ID，只输入了 30。你只需要输入容器 ID 的前几位数字，直到你输入的内容在所有容器中是唯一的。这是一个很好的快捷方式！

1.  检查运行的容器状态，Docker 只报告其他容器：

```py
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
094a13838376 rabbitmq:3-management "docker-entrypoint..." 2 days ago Up 2 days 4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp dreamy_easley
```

1.  容器没有运行，但也没有被删除。让我们来使用`docker ps -a`命令：

```py
$ docker ps -a
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
308a02f0e1a5 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 11 minutes ago Exited (143) 5 minutes ago romantic_kowalevski
548fc19e8b8d docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 12 minutes ago Exited (130) 12 minutes ago competent_keller
15c83ca72108 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 15 minutes ago Exited (130) 14 minutes ago peaceful_jennings
3191f204c661 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 18 minutes ago Exited (130) 16 minutes ago thirsty_hermann
b44f1da7613f docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 25 minutes ago Exited (130) 19 minutes ago
```

这列出了当前系统上的所有容器。实际上，我截断了我的列表，因为我有很多这样的容器！

1.  我们可以使用`docker restart`来重新启动我们的 Elasticsearch 容器：

```py
$ docker restart 30
30
```

1.  如果你检查`docker ps`，你会看到容器再次运行。

这很重要，因为这个容器在容器的文件系统中存储了 Elasticsearch 数据。通过停止和重新启动，这些数据不会丢失。因此，您可以停止以回收容器使用的资源（CPU 和内存），然后在以后的某个时间重新启动而不会丢失。

1.  无论是运行还是停止，容器都会占用磁盘空间。可以删除容器以回收磁盘空间。这可以使用`docker container rm <container-id>`来完成，但是只有在容器没有运行时才能删除容器。让我们尝试删除正在运行的容器：

```py
$ docker container rm 30
Error response from daemon: You cannot remove a running container 308a02f0e1a52fe8051d1d98fa19f8ac01ff52ec66737029caa07a8358740bce. Stop the container before attempting removal or force remove
```

1.  我们收到了有关容器运行的警告。我们可以使用一个标志来强制执行，但最好先停止它。停止可以确保容器内的应用程序干净地关闭：

```py
$ docker stop 30
30
$ docker rm 30
30
```

1.  现在，如果你回到 docker `ps -a`，Elasticsearch 容器不再在列表中，容器的磁盘空间被回收。

请注意，我们现在已经丢失了存储在该容器中的任何数据！这超出了本书的范围，但大多数容器可以被告知将数据存储在主机的文件系统上，因此我们不会丢失数据。

1.  容器的磁盘空间已经被删除，但是容器的镜像仍然在磁盘上。如果我们想创建另一个容器，这是很好的。但是如果你也想释放那个空间，你可以使用`docker images rm <image-id>`。回到 Docker 镜像结果，我们可以看到该镜像的 ID 是`06f0d8328d66`。以下删除该镜像，我们可以获得那个空间（在这种情况下是 539MB）：

```py
$ docker image rm 06
Untagged: docker.elastic.co/elasticsearch/elasticsearch:6.1.1
Untagged: docker.elastic.co/elasticsearch/elasticsearch@sha256:9e6c7d3c370a17736c67b2ac503751702e35a1336724741d00ed9b3d00434fcb
Deleted: sha256:06f0d8328d66a0f620075ee689ddb2f7535c31fb643de6c785deac8ba6db6a4c
Deleted: sha256:133d33f65d5a512c5fa8dc9eb8d34693a69bdb1a696006628395b07d5af08109
Deleted: sha256:ae2e02ab7e50b5275428840fd68fced2f63c70ca998a493d200416026c684a69
Deleted: sha256:7b6abb7badf2f74f1ee787fe0545025abcffe0bf2020a4e9f30e437a715c6d6a
```

现在镜像已经消失，我们也已经回收了那个空间。

请注意，如果还存在任何使用该镜像运行的容器，那么这将失败，这些容器可能正在运行或已停止。只是做一个`docker ps -a`可能不会显示有问题的容器，所以你可能需要使用`docker ps -a`来找到已停止的容器并首先删除它们。

# 还有更多...

在这一点上，你已经了解了足够多关于 Docker 的知识，可以变得非常危险！所以让我们继续研究如何创建我们自己的容器，并安装我们自己的应用程序。首先，让我们去看看如何将爬虫变成一个可以在容器中运行的微服务。

# 使用 Nameko 创建通用微服务

在接下来的几个步骤中，我们将创建一个可以作为 Docker 容器内的微服务运行的爬虫。但在直接进入火坑之前，让我们先看看如何使用一个名为 Nameko 的 Python 框架创建一个基本的微服务。

# 准备工作

我们将使用一个名为 Nameko 的 Python 框架（发音为[nah-meh-koh]）来实现微服务。与 Flask-RESTful 一样，使用 Nameko 实现的微服务只是一个类。我们将指示 Nameko 如何将该类作为服务运行，并且 Nameko 将连接一个消息总线实现，以允许客户端与实际的微服务进行通信。

默认情况下，Nameko 使用 RabbitMQ 作为消息总线。RabbitMQ 是一个高性能的消息总线，非常适合在微服务之间进行消息传递。它与我们之前在 SQS 中看到的模型类似，但更适合于位于同一数据中心的服务，而不是跨云。这实际上是 RabbitMQ 的一个很好的用途，因为我们现在倾向于在相同的环境中集群/扩展微服务，特别是在容器化集群中，比如 Docker 或 Kubernetes。

因此，我们需要在本地运行一个 RabbitMQ 实例。确保你有一个 RabbitMQ 容器运行，就像在之前的示例中展示的那样。

还要确保你已经安装了 Nameko：

```py
pip install Nameko
```

# 如何做到这一点

我们按照以下步骤进行操作：

1.  示例微服务实现在`10/01/hello_microservice.py`中。这是一个非常简单的服务，可以传递一个名字，微服务会回复`Hello, <name>!`。

1.  要运行微服务，我们只需要从终端执行以下命令（在脚本所在的目录中）：

```py
$nameko run hello_microservice
```

1.  Nameko 打开与指定微服务名称匹配的 Python 文件，并启动微服务。启动时，我们会看到几行输出：

```py
starting services: hello_microservice
Connected to amqp://guest:**@127.0.0.1:5672//
```

1.  这表明 Nameko 已经找到了我们的微服务，并且已经连接到了一个 AMQP 服务器（RabbitMQ）的 5672 端口（RabbitMQ 的默认端口）。微服务现在已经启动并且正在等待请求。

如果你进入 RabbitMQ API 并进入队列选项卡，你会看到 Nameko 已经自动为微服务创建了一个队列。

1.  现在我们必须做一些事情来请求微服务。我们将看两种方法来做到这一点。首先，Nameko 带有一个交互式 shell，让我们可以交互地向 Nameko 微服务发出请求。你可以在一个单独的终端窗口中使用以下命令启动 shell，与运行微服务的窗口分开：

```py
nameko shell
```

1.  你会看到一个交互式的 Python 会话开始，输出类似于以下内容：

```py
Nameko Python 3.6.1 |Anaconda custom (x86_64)| (default, Mar 22 2017, 19:25:17)
[GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.57)] shell on darwin
Broker: pyamqp://guest:guest@localhost
In [1]:
```

1.  在这个 shell 中，我们可以简单地将 Nameko 称为'n'。要与我们的服务交谈，我们发出以下声明：

```py
n.rpc.hello_microservice.hello(name='Mike')
```

1.  这告诉 Nameko 我们想要调用`hello_microservice`的`hello`方法。按下*Enter*后，你会得到以下结果：

```py
Out[1]: 'Hello, Mike!'
```

1.  如果你在运行服务的终端窗口中检查，你应该会看到额外的一行输出：

```py
Received a request from: Mike
```

1.  也可以在 Python 代码中调用微服务。在`10/01/say_hi.py`中有一个实现。用 Python 执行这个脚本会得到以下输出：

```py
$python say_hi.py
Hello, Micro-service Client!
```

那么让我们去看看这些是如何实现的。

# 它是如何工作的

让我们首先看一下`hello_microservice.py`中微服务的实现。实际上并没有太多的代码，所以这里是全部代码：

```py
from nameko.rpc import rpc

class HelloMicroService:
    name = "hello_microservice"    @rpc
  def hello(self, name):
        print('Received a request from: ' + name)
        return "Hello, {}!".format(name)
```

有两件事情要指出关于这个类。第一是声明`name = "hello_microservice"`。这是微服务的实际名称声明。这个成员变量被用来代替类名。

第二个是在`hello`方法上使用`@rpc`属性。这是一个 Nameko 属性，指定这个方法应该作为`rpc`风格的方法被微服务公开。因此，调用者会一直等待，直到从微服务接收到回复。还有其他实现方式，但是对于我们的目的，这是我们将使用的唯一方式。

当使用 nameko run 命令运行时，该模块将检查文件中带有 Nameko 属性的方法，并将它们连接到底层总线。

`say_hi.py`中的实现构建了一个可以调用服务的动态代理。代码如下：

```py
from nameko.standalone.rpc import ClusterRpcProxy

CONFIG = {'AMQP_URI': "amqp://guest:guest@localhost"}

with ClusterRpcProxy(CONFIG) as rpc:
    result = rpc.hello_microservice.hello("Micro-service Client")
    print(result)
```

动态代理是由`ClusterRpcProxy`类实现的。创建该类时，我们传递一个配置对象，该对象指定了服务所在的 AMQP 服务器的地址，在这种情况下，我们将这个实例称为变量`rpc`。然后，Nameko 动态识别下一个部分`.hello_microservice`作为微服务的名称（如在微服务类的名称字段中指定的）。

接下来的部分`.hello`代表要调用的方法。结合在一起，Nameko 调用`hello_microservice`的`hello`方法，传递指定的字符串，由于这是一个 RPC 代理，它会等待接收到回复。

远程过程调用，简称 RPC，会一直阻塞，直到结果从其他系统返回。与发布模型相比，发布模型中消息被发送后发送应用程序继续进行。

# 还有更多...

在 Nameko 中有很多好东西，我们甚至还没有看到。一个非常有用的因素是，Nameko 运行多个微服务实例的监听器。撰写本文时，默认值为 10。在底层，Nameko 将来自微服务客户端的请求发送到 RabbitMQ 队列，其中将有 10 个同时的请求处理器监听该队列。如果有太多的请求需要同时处理，RabbitMQ 将保留消息，直到 Nameko 回收现有的微服务实例来处理排队的消息。为了增加微服务的可伸缩性，我们可以通过微服务的配置简单地增加工作人员的数量，或者在另一个 Docker 容器中运行一个单独的 Nameko 微服务容器，或者在另一台计算机系统上运行。

# 创建一个抓取微服务

现在让我们把我们的抓取器变成一个 Nameko 微服务。这个抓取微服务将能够独立于 API 的实现而运行。这将允许抓取器独立于 API 的实现进行操作、维护和扩展。

# 如何做

我们按照以下步骤进行：

1.  微服务的代码很简单。代码在`10/02/call_scraper_microservice.py`中，如下所示：

```py
from nameko.rpc import rpc
import sojobs.scraping 

class ScrapeStackOverflowJobListingsMicroService:
    name = "stack_overflow_job_listings_scraping_microservice"    @rpc
  def get_job_listing_info(self, job_listing_id):
        listing = sojobs.scraping.get_job_listing_info(job_listing_id)
        print(listing)
        return listing

if __name__ == "__main__":
    print(ScrapeStackOverflowJobListingsMicroService("122517"))
```

1.  我们创建了一个类来实现微服务，并给它一个单一的方法`get_job_listing_info`。这个方法简单地包装了`sojobs.scraping`模块中的实现，但是给它一个`@rpc`属性，以便 Nameko 在微服务总线上公开该方法。这可以通过打开终端并使用 Nameko 运行服务来运行。

```py
$ nameko run scraper_microservice
 starting services: stack_overflow_job_listings_scraping_microservice
 Connected to amqp://guest:**@127.0.0.1:5672//
```

1.  现在我们可以使用`10/02/call_scraper_microservice.py`脚本中的代码运行抓取器。文件中的代码如下：

```py
from nameko.standalone.rpc import ClusterRpcProxy

CONFIG = {'AMQP_URI': "amqp://guest:guest@localhost"}

with ClusterRpcProxy(CONFIG) as rpc:
    result = rpc.stack_overflow_job_listings_scraping_microservice.get_job_listing_info("122517")
    print(result)
```

1.  这基本上与上一个教程中客户端的代码相同，但是更改了微服务和方法的名称，并当然传递了特定的工作列表 ID。运行时，您将看到以下输出（已截断）：

```py
{"ID": "122517", "JSON": {"@context": "http://schema.org", "@type": "JobPosting", "title": "SpaceX Enterprise Software Engineer, Full Stack", "skills": ["c#", "sql", "javascript", "asp.net", "angularjs"], 

...
```

1.  就像这样，我们已经创建了一个从 StackOverflow 获取工作列表的微服务！

# 还有更多...

这个微服务只能使用`ClusterRpcProxy`类调用，不能被任何人通过互联网甚至本地使用 REST 调用。我们将在即将到来的教程中解决这个问题，在那里我们将在一个容器中创建一个 REST API，该 API 将与另一个运行在另一个容器中的微服务进行通信。

# 创建一个抓取容器

现在我们为我们的抓取微服务创建一个容器。我们将学习 Dockerfile 以及如何指示 Docker 如何构建容器。我们还将研究如何为我们的 Docker 容器提供主机名，以便它们可以通过 Docker 集成的 DNS 系统相互找到。最后但并非最不重要的是，我们将学习如何配置我们的 Nameko 微服务，以便与另一个容器中的 RabbitMQ 通信，而不仅仅是在本地主机上。

# 准备工作

我们要做的第一件事是确保 RabbitMQ 在一个容器中运行，并分配给一个自定义的 Docker 网络，连接到该网络的各种容器将相互通信。除了许多其他功能外，它还提供了软件定义网络（SDN）功能，以在容器、主机和其他系统之间提供各种类型的集成。

Docker 自带了几个预定义的网络。您可以使用`docker network ls`命令查看当前安装的网络：

```py
$ docker network ls
NETWORK ID   NAME                                     DRIVER  SCOPE
bc3bed092eff bridge                                   bridge  local
26022f784cc1 docker_gwbridge                          bridge  local
448d8ce7f441 dockercompose2942991694582470787_default bridge  local
4e549ce87572 dockerelkxpack_elk                       bridge  local
ad399a431801 host                                     host    local
rbultxlnlhfb ingress                                  overlay swarm
389586bebcf2 none                                     null    local
806ff3ec2421 stackdockermaster_stack                  bridge  local
```

为了让我们的容器相互通信，让我们创建一个名为`scraper-net`的新桥接网络。

```py
$ docker network create --driver bridge scraper-net
e4ea1c48395a60f44ec580c2bde7959641c4e1942cea5db7065189a1249cd4f1
```

现在，当我们启动一个容器时，我们使用`--network`参数将其连接到`scraper-net`：

```py
$docker run -d --name rabbitmq --network scrape-rnet -p 15672:15672 -p 5672:5672 rabbitmq:3-management
```

这个容器现在连接到`scraper-net`网络和主机网络。因为它也连接到主机，所以仍然可以从主机系统连接到它。

还要注意，我们使用了`--name rabbitmq`作为一个选项。这给了这个容器名字`rabbitmq`，但 Docker 也会解析来自连接到`scraper-net`的其他容器的 DNS 查询，以便它们可以找到这个容器！

现在让我们把爬虫放到一个容器中。

# 如何做到这一点

我们按照以下步骤进行配方：

1.  我们创建容器的方式是创建一个`dockerfile`，然后使用它告诉 Docker 创建一个容器。我在`10/03`文件夹中包含了一个 Dockerfile。内容如下（我们将在*它是如何工作*部分检查这意味着什么）：

```py
FROM python:3 WORKDIR /usr/src/app

RUN pip install nameko BeautifulSoup4 nltk lxml
RUN python -m nltk.downloader punkt -d /usr/share/nltk_data all

COPY 10/02/scraper_microservice.py .
COPY modules/sojobs sojobs

CMD ["nameko", "run", "--broker", "amqp://guest:guest@rabbitmq", "scraper_microservice"]
```

1.  要从这个 Dockerfile 创建一个镜像/容器，在终端中，在`10/03`文件夹中，运行以下命令：

```py
$docker build ../.. -f Dockerfile  -t scraping-microservice
```

1.  这告诉 Docker，我们想要根据给定的 Dockerfile 中的指令*构建*一个容器（用-f 指定）。创建的镜像由指定

`-t scraping-microservice`。`build`后面的`../..`指定了构建的上下文。在构建时，我们将文件复制到容器中。这个上下文指定了复制相对于的主目录。当你运行这个命令时，你会看到类似以下的输出：

```py
Sending build context to Docker daemon 2.128MB
Step 1/8 : FROM python:3
 ---> c1e459c00dc3
Step 2/8 : WORKDIR /usr/src/app
 ---> Using cache
 ---> bf047017017b
Step 3/8 : RUN pip install nameko BeautifulSoup4 nltk lxml
 ---> Using cache
 ---> a30ce09e2f66
Step 4/8 : RUN python -m nltk.downloader punkt -d /usr/share/nltk_data all
 ---> Using cache
 ---> 108b063908f5
Step 5/8 : COPY 10/07/. .
 ---> Using cache
 ---> 800a205d5283
Step 6/8 : COPY modules/sojobs sojobs
 ---> Using cache
 ---> 241add5458a5
Step 7/8 : EXPOSE 5672
 ---> Using cache
 ---> a9be801d87af
Step 8/8 : CMD nameko run --broker amqp://guest:guest@rabbitmq scraper_microservice
 ---> Using cache
 ---> 0e1409911ac9
Successfully built 0e1409911ac9
Successfully tagged scraping-microservice:latest
```

1.  这可能需要一些时间，因为构建过程需要将所有的 NLTK 文件下载到容器中。要检查镜像是否创建，可以运行以下命令：

```py
$ docker images | head -n 2
REPOSITORY            TAG    IMAGE ID     CREATED     SIZE
scraping-microservice latest 0e1409911ac9 3 hours ago 4.16GB
```

1.  请注意，这个容器的大小是 4.16GB。这个镜像是基于`Python:3`容器的，可以看到大小为`692MB`：

```py
$ docker images | grep python
 python 3 c1e459c00dc3 2 weeks ago 692MB
```

这个容器的大部分大小是因为包含了 NTLK 数据文件。

1.  现在我们可以使用以下命令将这个镜像作为一个容器运行：

```py
03 $ docker run --network scraper-net scraping-microservice
starting services: stack_overflow_job_listings_scraping_microservice
Connected to amqp://guest:**@rabbitmq:5672//
```

我们组合的爬虫现在在这个容器中运行，这个输出显示它已经连接到一个名为`rabbitmq`的系统上的 AMQP 服务器。

1.  现在让我们测试一下这是否有效。在另一个终端窗口中运行 Nameko shell：

```py
03 $ nameko shell
Nameko Python 3.6.1 |Anaconda custom (x86_64)| (default, Mar 22 2017, 19:25:17)
[GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.57)] shell on darwin
Broker: pyamqp://guest:guest@localhost
In [1]:
```

1.  现在，在提示符中输入以下内容来调用微服务：

```py
n.rpc.stack_overflow_job_listings_scraping_microservice.get_job_listing_info("122517")
```

1.  由于抓取的结果，你会看到相当多的输出（以下是截断的）：

```py
Out[1]: '{"ID": "122517", "JSON": {"@context": "http://schema.org", "@type": "JobPosting", "title": "SpaceX Enterprise Software Engineer, Full Stack", "skills": ["c#", "sql", "javascript", "asp.net"
```

恭喜！我们现在已经成功调用了我们的爬虫微服务。现在，让我们讨论这是如何工作的，以及 Dockerfile 是如何构建微服务的 Docker 镜像的。

# 它是如何工作的

让我们首先讨论 Dockerfile，通过在构建过程中告诉 Docker 要做什么来逐步了解它的内容。第一行：

```py
FROM python:3
```

这告诉 Docker，我们想要基于 Docker Hub 上找到的`Python:3`镜像构建我们的容器镜像。这是一个预先构建的 Linux 镜像，安装了 Python 3。下一行告诉 Docker，我们希望所有的文件操作都是相对于`/usr/src/app`文件夹的。

```py
WORKDIR /usr/src/app
```

在构建镜像的这一点上，我们已经安装了一个基本的 Python 3。然后我们需要安装我们的爬虫使用的各种库，所以下面告诉 Docker 运行 pip 来安装它们：

```py
RUN pip install nameko BeautifulSoup4 nltk lxml
```

我们还需要安装 NLTK 数据文件：

```py
RUN python -m nltk.downloader punkt -d /usr/share/nltk_data all
```

接下来，我们将实现我们的爬虫复制进去。以下是将`scraper_microservice.py`文件从上一个配方的文件夹复制到容器镜像中。

```py
COPY 10/02/scraper_microservice.py .
```

这也取决于`sojobs`模块，因此我们也复制它：

```py
COPY modules/sojobs sojobs
```

最后一行告诉 Docker 在启动容器时要运行的命令：

```py
CMD ["nameko", "run", "--broker", "amqp://guest:guest@rabbitmq", "scraper_microservice"]
```

这告诉 Nameko 在`scraper_microservice.py`中运行微服务，并且还与名为`rabbitmq`的系统上的 RabbitMQ 消息代理进行通信。由于我们将 scraper 容器附加到 scraper-net 网络，并且还对 RabbitMQ 容器执行了相同操作，Docker 为我们连接了这两个容器！

最后，我们从 Docker 主机系统中运行了 Nameko shell。当它启动时，它报告说它将与 AMQP 服务器（RabbitMQ）通信`pyamqp://guest:guest@localhost`。当我们在 shell 中执行命令时，Nameko shell 将该消息发送到 localhost。

那么它如何与容器中的 RabbitMQ 实例通信呢？当我们启动 RabbitMQ 容器时，我们告诉它连接到`scraper-net`网络。它仍然连接到主机网络，因此只要我们在启动时映射了`5672`端口，我们仍然可以与 RabbitMQ 代理进行通信。

我们在另一个容器中的微服务正在 RabbitMQ 容器中监听消息，然后响应该容器，然后由 Nameko shell 接收。这很酷，不是吗？

# 创建 API 容器

此时，我们只能使用 AMQP 或使用 Nameko shell 或 Nameko `ClusterRPCProxy`类与我们的微服务进行通信。因此，让我们将我们的 Flask-RESTful API 放入另一个容器中，与其他容器一起运行，并进行 REST 调用。这还需要我们运行一个 Elasticsearch 容器，因为该 API 代码还与 Elasticsearch 通信。

# 准备就绪

首先让我们在附加到`scraper-net`网络的容器中启动 Elasticsearch。我们可以使用以下命令启动它：

```py
$ docker run -e ELASTIC_PASSWORD=MagicWord --name=elastic --network scraper-net  -p 9200:9200 -p 9300:9300 docker.elastic.co/elasticsearch/elasticsearch:6.1.1
```

Elasticsearch 现在在我们的`scarper-net`网络上运行。其他容器中的应用程序可以使用名称 elastic 访问它。现在让我们继续创建 API 的容器。

# 如何做

我们按照以下步骤进行：

1.  在`10/04`文件夹中有一个`api.py`文件，该文件实现了一个修改后的 Flask-RESTful API，但进行了几处修改。让我们检查 API 的代码：

```py
from flask import Flask
from flask_restful import Resource, Api
from elasticsearch import Elasticsearch
from nameko.standalone.rpc import ClusterRpcProxy

app = Flask(__name__)
api = Api(app)

CONFIG = {'AMQP_URI': "amqp://guest:guest@rabbitmq"}

class JobListing(Resource):
    def get(self, job_listing_id):
        print("Request for job listing with id: " + job_listing_id)

        es = Elasticsearch(hosts=["elastic"])
        if (es.exists(index='joblistings', doc_type='job-listing', id=job_listing_id)):
            print('Found the document in Elasticsearch')
            doc =  es.get(index='joblistings', doc_type='job-listing', id=job_listing_id)
            return doc['_source']

        print('Not found in Elasticsearch, trying a scrape')
        with ClusterRpcProxy(CONFIG) as rpc:
            listing = rpc.stack_overflow_job_listings_scraping_microservice.get_job_listing_info(job_listing_id)
            print("Microservice returned with a result - storing in Elasticsearch")
            es.index(index='joblistings', doc_type='job-listing', id=job_listing_id, body=listing)
            return listing

api.add_resource(JobListing, '/', '/joblisting/<string:job_listing_id>')

if __name__ == '__main__':
    print("Starting the job listing API ...")
    app.run(host='0.0.0.0', port=8080, debug=True)
```

1.  第一个变化是 API 上只有一个方法。我们现在将重点放在`JobListing`方法上。在该方法中，我们现在进行以下调用以创建 Elasticsearch 对象：

```py
es = Elasticsearch(hosts=["elastic"])
```

1.  默认构造函数假定 Elasticsearch 服务器在 localhost 上。此更改现在将其指向 scraper-net 网络上名为 elastic 的主机。

1.  第二个变化是删除对 sojobs 模块中函数的调用。相反，我们使用`Nameko ClusterRpcProxy`对象调用在 scraper 容器内运行的 scraper 微服务。该对象传递了一个配置，将 RPC 代理指向 rabbitmq 容器。

1.  最后一个变化是 Flask 应用程序的启动：

```py
    app.run(host='0.0.0.0', port=8080, debug=True)
```

1.  默认连接到 localhost，或者 127.0.0.1。在容器内部，这不会绑定到我们的`scraper-net`网络，甚至不会绑定到主机网络。使用`0.0.0.0`将服务绑定到所有网络接口，因此我们可以通过容器上的端口映射与其通信。端口也已移至`8080`，这是比 5000 更常见的 REST API 端口。

1.  将 API 修改为在容器内运行，并与 scraper 微服务通信后，我们现在可以构建容器。在`10/04`文件夹中有一个 Dockerfile 来配置容器。其内容如下：

```py
FROM python:3 WORKDIR /usr/src/app

RUN pip install Flask-RESTful Elasticsearch Nameko

COPY 10/04/api.py .

CMD ["python", "api.py"]
```

这比以前容器的 Dockerfile 简单。该容器没有 NTLK 的所有权重。最后，启动只需执行`api.py`文件。

1.  使用以下内容构建容器：

```py
$docker build ../.. -f Dockerfile -t scraper-rest-api
```

1.  然后我们可以使用以下命令运行容器：

```py
$docker run -d -p 8080:8080 --network scraper-net scraper-rest-api
```

1.  现在让我们检查一下我们的所有容器是否都在运行：

```py
$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
55e438b4afcd scraper-rest-api "python -u api.py" 46 seconds ago Up 45 seconds 0.0.0.0:8080->8080/tcp vibrant_sammet
bb8aac5b7518 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 3 hours ago Up 3 hours 0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp elastic
ac4f51c1abdc scraping-microservice "nameko run --brok..." 3 hours ago Up 3 hours thirsty_ritchie
18c2f01f58c7 rabbitmq:3-management "docker-entrypoint..." 3 hours ago Up 3 hours 4369/tcp, 5671/tcp, 0.0.0.0:5672->5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp rabbitmq
```

1.  现在，从主机终端上，我们可以向 REST 端点发出 curl 请求（输出已截断）：

```py
$ curl localhost:8080/joblisting/122517
"{\"ID\": \"122517\", \"JSON\": {\"@context\": \"http://schema.org\", \"@type\": \"JobPosting\", \"title\": \"SpaceX Enterprise Software Engineer, Full Stack\", \"skills\": [\"c#\", \"sql\", \"javas
```

然后我们就完成了。我们已经将 API 和功能容器化，并在容器中运行了 RabbitMQ 和 Elasticsearch。

# 还有更多...

这种类型的容器化对于操作的设计和部署是一个巨大的优势，但是我们仍然需要创建许多 Docker 文件、容器和网络来连接它们，并独立运行它们。幸运的是，我们可以使用 docker-compose 来简化这个过程。我们将在下一个步骤中看到这一点。

# 使用 docker-compose 在本地组合和运行爬虫

Compose 是一个用于定义和运行多容器 Docker 应用程序的工具。使用 Compose，您可以使用 YAML 文件配置应用程序的服务。然后，通过一个简单的配置文件和一个命令，您可以从配置中创建和启动所有服务。

# 准备就绪

使用 Compose 的第一件事是确保已安装。Compose 会随 Docker for macOS 自动安装。在其他平台上，可能已安装或未安装。您可以在以下网址找到说明：[`docs.docker.com/compose/install/#prerequisites`](https://docs.docker.com/compose/install/#prerequisites)。

此外，请确保我们之前创建的所有现有容器都没有在运行，因为我们将创建新的容器。

# 如何做到这一点

我们按照以下步骤进行：

1.  Docker Compose 使用`docker-compose.yml`文件告诉 Docker 如何将容器组合为`services`。在`10/05`文件夹中有一个`docker-compose.yml`文件，用于将我们的爬虫的所有部分作为服务启动。以下是文件的内容：

```py
version: '3' services:
 api: image: scraper-rest-api
  ports:
  - "8080:8080"
  networks:
  - scraper-compose-net    scraper:
 image: scraping-microservice
  depends_on:
  - rabbitmq
  networks:
  - scraper-compose-net    elastic:
 image: docker.elastic.co/elasticsearch/elasticsearch:6.1.1
  ports:
  - "9200:9200"
  - "9300:9300"
  networks:
  - scraper-compose-net    rabbitmq:
 image: rabbitmq:3-management
  ports:
  - "15672:15672"
  networks:
  - scraper-compose-net   networks:
 scraper-compose-net: driver: bridge
```

使用 Docker Compose，我们不再考虑容器，而是转向与服务一起工作。在这个文件中，我们描述了四个服务（api、scraper、elastic 和 rabbitmq）以及它们的创建方式。每个服务的图像标签告诉 Compose 要使用哪个 Docker 图像。如果需要映射端口，那么我们可以使用`ports`标签。`network`标签指定要连接服务的网络，在这种情况下，文件中还声明了一个`bridged`网络。最后要指出的一件事是 scraper 服务的`depends_on`标签。该服务需要在之前运行`rabbitmq`服务，这告诉 docker compose 确保按指定顺序进行。

1.  现在，要启动所有内容，打开一个终端并从该文件夹运行以下命令：

```py
    $ docker-compose up
```

1.  Compose 在读取配置并弄清楚要做什么时会暂停一会儿，然后会有相当多的输出，因为每个容器的输出都将流式传输到这个控制台。在输出的开头，您将看到类似于以下内容：

```py
Starting 10_api_1 ...
 Recreating elastic ...
 Starting rabbitmq ...
 Starting rabbitmq
 Recreating elastic
 Starting rabbitmq ... done
 Starting 10_scraper_1 ...
 Recreating elastic ... done
 Attaching to rabbitmq, 10_api_1, 10_scraper_1, 10_elastic_1
```

1.  在另一个终端中，您可以发出`docker ps`命令来查看已启动的容器：

```py
$ docker ps
 CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
 2ed0d456ffa0 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 3 minutes ago Up 2 minutes 0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp 10_elastic_1
 8395989fac8d scraping-microservice "nameko run --brok..." 26 minutes ago Up 3 minutes 10_scraper_1
 4e9fe8479db5 rabbitmq:3-management "docker-entrypoint..." 26 minutes ago Up 3 minutes 4369/tcp, 5671-5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp rabbitmq
 0b0df48a7201 scraper-rest-api "python -u api.py" 26 minutes ago Up 3 minutes 0.0.0.0:8080->8080/tcp 10_api_1
```

注意服务容器的名称。它们被两个不同的标识符包裹。前缀只是运行组合的文件夹，本例中为 10（用于'10_'前缀）。您可以使用-p 选项来更改这个，以指定其他内容。尾随的数字是该服务的容器实例编号。在这种情况下，我们每个服务只启动了一个容器，所以这些都是 _1。不久之后，当我们进行扩展时，我们将看到这一点发生变化。

您可能会问：如果我的服务名为`rabbitmq`，而 Docker 创建了一个名为`10_rabbitmq_1`的容器，那么使用`rabbitmq`作为主机名的微服务如何连接到 RabbitMQ 实例？在这种情况下，Docker Compose 已经为您解决了这个问题，因为它知道`rabbitmq`需要被转换为`10_rabbitmq_1`。太棒了！

1.  作为启动此环境的一部分，Compose 还创建了指定的网络：

```py
$ docker network ls | head -n 2
 NETWORK ID NAME DRIVER SCOPE
 0e27be3e30f2 10_scraper-compose-net bridge local
```

如果我们没有指定网络，那么 Compose 将创建一个默认网络并将所有内容连接到该网络。在这种情况下，这将正常工作。但在更复杂的情况下，这个默认值可能不正确。

1.  现在，此时一切都已经启动并运行。让我们通过调用 REST 抓取 API 来检查一切是否正常运行：

```py
$ curl localhost:8080/joblisting/122517
 "{\"ID\": \"122517\", \"JSON\": {\"@context\": \"http://schema.org\", \"@type\": \"JobPosting\", \"title\": \"SpaceX Enterprise Software Engineer, Full Stack\", \"
...
```

1.  同时，让我们通过检查工作列表的索引来确认 Elasticsearch 是否正在运行，因为我们已经请求了一个：

```py
$ curl localhost:9200/joblisting
{"error":{"root_cause":{"type":"index_not_found_exception","reason":"no such index","resource.type":"index_or_alias","resource.id":"joblisting","index_uuid":"_na_","index":"j
...
```

1.  我们还可以使用 docker-compose 来扩展服务。如果我们想要添加更多微服务容器以增加处理请求的数量，我们可以告诉 Compose 增加 scraper 服务容器的数量。以下命令将 scraper 容器的数量增加到 3 个：

```py
docker-compose up --scale scraper=3
```

1.  Compose 将会考虑一会儿这个请求，然后发出以下消息，说明正在启动另外两个 scraper 服务容器（随后会有大量输出来自这些容器的初始化）：

```py
10_api_1 is up-to-date
10_elastic_1 is up-to-date
10_rabbitmq_1 is up-to-date
Starting 10_scraper_1 ... done
Creating 10_scraper_2 ...
Creating 10_scraper_3 ...
Creating 10_scraper_2 ... done
Creating 10_scraper_3 ... done
Attaching to 10_api_1, 10_elastic_1, 10_rabbitmq_1, 10_scraper_1, 10_scraper_3, 10_scraper_2
```

1.  `docker ps`现在将显示三个正在运行的 scraper 容器：

```py
Michaels-iMac-2:09 michaelheydt$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
b9c2da0c9008 scraping-microservice "nameko run --brok..." About a minute ago Up About a minute 10_scraper_2
643221f85364 scraping-microservice "nameko run --brok..." About a minute ago Up About a minute 10_scraper_3
73dc31fb3d92 scraping-microservice "nameko run --brok..." 6 minutes ago Up 6 minutes 10_scraper_1
5dd0db072483 scraper-rest-api "python api.py" 7 minutes ago Up 7 minutes 0.0.0.0:8080->8080/tcp 10_api_1
d8e25b6ce69a rabbitmq:3-management "docker-entrypoint..." 7 minutes ago Up 7 minutes 4369/tcp, 5671-5672/tcp, 15671/tcp, 25672/tcp, 0.0.0.0:15672->15672/tcp 10_rabbitmq_1
f305f81ae2a3 docker.elastic.co/elasticsearch/elasticsearch:6.1.1 "/usr/local/bin/do..." 7 minutes ago Up 7 minutes 0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp 10_elastic_1
```

1.  现在我们可以看到我们有三个名为`10_scraper_1`、`10_scraper_2`和`10_scraper_3`的容器。很酷！如果你进入 RabbitMQ 管理界面，你会看到有三个连接：

![RabbitMQ 中的 Nameko 队列请注意每个队列都有不同的 IP 地址。在像我们创建的桥接网络上，Compose 会在`172.23.0`网络上分配 IP 地址，从`.2`开始。

操作上，所有来自 API 的抓取请求都将被路由到 rabbitmq 容器，实际的 RabbitMQ 服务将把消息传播到所有活动连接，因此传播到所有三个容器，帮助我们扩展处理能力。

服务实例也可以通过发出一个较小数量的容器的规模值来缩减，Compose 将会响应并删除容器，直到达到指定的值。

当一切都完成时，我们可以告诉 Docker Compose 关闭所有内容：

```py
$ docker-compose down
Stopping 10_scraper_1 ... done
Stopping 10_rabbitmq_1 ... done
Stopping 10_api_1 ... done
Stopping 10_elastic_1 ... done
Removing 10_scraper_1 ... done
Removing 10_rabbitmq_1 ... done
Removing 10_api_1 ... done
Removing 10_elastic_1 ... done
Removing network 10_scraper-compose-net
```

执行`docker ps`现在将显示所有容器都已被移除。

# 还有更多...

我们几乎没有涉及 Docker 和 Docker Compose 的许多功能，甚至还没有开始研究使用 Docker swarm 等服务。虽然 docker Compose 很方便，但它只在单个主机上运行容器，最终会有可扩展性的限制。Docker swarm 将执行类似于 Docker Compose 的操作，但是在集群中跨多个系统进行操作，从而实现更大的可扩展性。但希望这让你感受到了 Docker 和 Docker Compose 的价值，以及在创建灵活的抓取服务时它们的价值。
