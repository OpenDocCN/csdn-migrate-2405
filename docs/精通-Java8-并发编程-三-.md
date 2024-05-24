# 精通 Java8 并发编程（三）

> 原文：[`zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A`](https://zh.annas-archive.org/md5/BFECC9856BE4118734A8147A2EEBA11A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：分阶段运行任务-Phaser 类

并发 API 中最重要的元素是为程序员提供的同步机制。**同步**是协调两个或多个任务以获得期望的结果。当必须按预定义顺序执行两个或多个任务时，或者当只有一个线程可以同时执行代码片段或修改一块内存块时，可以同步两个或多个任务的执行，或者同步对共享资源的访问。Java 8 并发 API 提供了许多同步机制，从基本的`synchronized`关键字或`Lock`接口及其实现来保护关键部分，到更高级的`CyclicBarrier`或`CountDownLatch`类，允许您同步不同任务的执行顺序。在 Java 7 中，并发 API 引入了`Phaser`类。该类提供了一个强大的机制（**phaser**）来执行分阶段的任务。任务可以要求 Phaser 类等待直到所有其他参与者完成该阶段。在本章中，我们将涵盖以下主题：

+   `Phaser`类的介绍

+   第一个示例-关键词提取算法

+   第二个示例-遗传算法

# `Phaser`类的介绍

`Phaser`类是一种同步机制，旨在以并发方式控制可以分阶段执行的算法。如果您有一个具有明确定义步骤的过程，因此您必须在开始第一个步骤之前完成它，然后依此类推，您可以使用此类来制作过程的并发版本。`Phaser`类的主要特点包括：

+   Phaser 必须知道它需要控制的任务数量。Java 将此称为参与者的注册。参与者可以随时在 phaser 中注册。

+   任务必须在完成阶段时通知 phaser。Phaser 将使该任务休眠，直到所有参与者完成该阶段为止。

+   在内部，phaser 保存一个整数，用于存储该阶段已经进行的阶段变化次数。

+   参与者可以随时离开 phaser 的控制。Java 将此称为参与者的注销。

+   当 phaser 进行阶段变化时，您可以执行自定义代码。

+   您可以控制 phaser 的终止。如果 phaser 被终止，将不会接受新的参与者，并且任务之间也不会进行同步。

+   您可以使用一些方法来了解 phaser 的状态和参与者数量。

## 参与者的注册和注销

正如我们之前提到的，phaser 必须知道它需要控制的任务数量。它必须知道有多少不同的线程正在执行分阶段算法，以正确地控制同时的阶段变化。

Java 将此过程称为参与者的注册。通常情况下，参与者在执行开始时注册，但是参与者可以随时注册。

您可以使用不同的方法注册参与者：

+   当您创建`Phaser`对象时：`Phaser`类提供了四种不同的构造函数。其中两种是常用的：

+   `Phaser()`:此构造函数创建一个没有参与者的 phaser

+   `Phaser(int parties)`:此构造函数创建一个具有给定参与者数量的 phaser

+   明确地，使用其中一种方法：

+   `bulkRegister(int parties)`:同时注册给定数量的新参与者

+   `register()`:注册一个新的参与者

当由 phaser 控制的任务之一完成其执行时，它必须从 phaser 中注销。如果不这样做，phaser 将在下一个阶段变化中无休止地等待它。要注销参与者，可以使用`arriveAndDeregister()`方法。您可以使用此方法指示 phaser，该任务已完成当前阶段，并且不会参与下一个阶段。

## 同步阶段变化

phaser 的主要目的是以并发方式清晰地划分为阶段的算法的实现。在所有任务完成前一个阶段之前，没有一个任务可以进入下一个阶段。`Phaser`类提供了三种方法来表示任务已完成阶段：`arrive()`、`arriveAndDeregister()`和`arriveAndAwaitAdvance()`。如果其中一个任务没有调用这些方法之一，其他参与者任务将被 phaser 无限期地阻塞。要进入下一个阶段，使用以下方法：

+   `arriveAndAwaitAdvance()`: 任务使用此方法向 phaser 指示，它已完成当前阶段，并希望继续下一个阶段。phaser 将阻塞任务，直到所有参与者任务调用了同步方法之一。

+   `awaitAdvance(int phase)`: 任务使用此方法向 phaser 指示，如果传递的数字和 phaser 的当前阶段相等，则希望等待当前阶段的完成。如果它们不相等，此方法将立即返回。

## 其他功能

当所有参与者任务完成一个阶段的执行并在继续下一个阶段之前，`Phaser`类执行`onAdvance()`方法。此方法接收以下两个参数：

+   `phase`：这是已完成的阶段编号。第一个阶段是编号零

+   `registeredParties`：这表示参与者任务的数量

如果您想在两个阶段之间执行一些代码，例如对数据进行排序或转换，可以实现自己的 phaser，扩展`Phaser`类并覆盖此方法。

phaser 可以处于两种状态：

+   **活动**：当创建 phaser 并注册新参与者并继续进行直到终止时，phaser 进入此状态。在此状态下，它接受新的参与者并按照之前的说明工作。

+   **终止**：当`onAdvance()`方法返回`true`值时，phaser 进入此状态。默认情况下，当所有参与者已注销时，它返回`true`值。

### 注意

当 phaser 处于终止状态时，新参与者的注册不起作用，并且同步方法会立即返回。

最后，`Phaser`类提供了一些方法来获取有关 phaser 状态和参与者的信息：

+   `getRegisteredParties()`: 此方法返回 phaser 中的参与者数量

+   `getPhase()`: 此方法返回当前阶段的编号

+   `getArrivedParties()`: 此方法返回已完成当前阶段的参与者数量

+   `getUnarrivedParties()`: 此方法返回尚未完成当前阶段的参与者数量

+   `isTerminated()`: 如果 phaser 处于终止状态，则此方法返回`true`值，否则返回`false`

# 第一个示例 - 关键字提取算法

在本节中，您将使用 phaser 来实现**关键字提取算法**。这类算法的主要目的是从文本文档或文档集合中提取单词，以更好地定义文档在集合中的文档。这些术语可用于总结文档、对其进行聚类或改进信息搜索过程。

从集合中提取文档关键字的最基本算法（但现在仍然常用）是基于**TF-IDF**度量，其中：

+   **TF**（代表**词项频率**）是单词在文档中出现的次数。

+   **DF**（代表**文档频率**）是包含单词的文档数量。**IDF**（代表**逆文档频率**）度量了单词提供的信息，以区分文档与其他文档。如果一个词很常见，它的 IDF 将很低，但如果这个词只出现在少数文档中，它的 IDF 将很高。

单词*t*在文档*d*中的 TF-IDF 可以使用以下公式计算：

![第一个示例 - 关键词提取算法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00014.jpeg)

上述公式中使用的属性可以解释如下：

+   *F**[t,d]*是单词*t*在文档*d*中出现的次数

+   *N*是集合中文档的数量

+   *n**[t]*是包含单词*t*的文档数量

要获取文档的关键词，可以选择 TF-IDF 值较高的单词。

您将要实现的算法将执行以下阶段，计算文档集合中的最佳关键词：

+   **第一阶段**：解析所有文档并提取所有单词的 DF。请注意，只有在解析所有文档后，您才会获得确切的值。

+   **第二阶段**：计算所有文档中所有单词的 TF-IDF。选择每个文档的 10 个关键词（TF-IDF 值最高的 10 个单词）。

+   **第三阶段**：获取最佳关键词列表。我们认为那些是出现在更多文档中的单词。

为了测试算法，我们将使用维基百科关于电影信息的页面作为文档集合。我们在第四章中使用了相同的集合，*从任务中获取数据 - Callable 和 Future 接口*。该集合由 100,673 个文档组成。我们已经将每个维基百科页面转换为文本文件。您可以下载包含有关该书的所有信息的文档集合。

您将要实现算法的两个不同版本：基本的串行版本和使用`Phaser`类的并发版本。之后，我们将比较两个版本的执行时间，以验证并发性能更好。

## 常见类

算法的两个版本共享一些通用功能，用于解析文档并存储有关文档、关键词和单词的信息。这些通用类包括：

+   存储包含文档名称和构成文档的单词的`Document`类

+   存储单词字符串和该单词的度量（TF，DF 和 TF-IDF）的`Word`类

+   存储单词字符串和该单词作为关键词出现在的文档数量的`Keyword`类

+   提取文档中的单词的`DocumentParser`类

让我们更详细地看看这些类。

### 单词类

`Word`类存储有关单词的信息。这些信息包括整个单词以及影响它的度量，即它在文档中的 TF，它的全局 DF 和结果 TF-IDF。

这个类实现了`Comparable`接口，因为我们将对单词数组进行排序，以获取 TF-IDF 值较高的单词。参考以下代码：

```java
public class Word implements Comparable<Word> {
```

然后，我们声明了该类的属性并实现了 getter 和 setter（这些未包含在内）：

```java
    private String word;
    private int tf;
    private int df;
    private double tfIdf;
```

我们已经实现了其他感兴趣的方法如下：

+   该类的构造函数，初始化单词（使用参数接收的单词）和`df`属性（值为`1`）。

+   `addTf()`方法，增加`tf`属性。

+   `merge()`方法接收一个`Word`对象并合并来自两个不同文档的相同单词。它将两个对象的`tf`和`df`属性相加。

然后，我们实现了`setDf()`方法的特殊版本。它接收`df`属性的值和集合中文档的总数，并计算`tfIdf`属性：

```java
    public void setDf(int df, int N) {
        this.df = df;
        tfIdf = tf * Math.log(Double.valueOf(N) / df);
    }
```

最后，我们实现`compareTo()`方法。我们希望单词按`tfIdf`属性从高到低排序：

```java
    @Override
    public int compareTo(Word o) {
        return Double.compare(o.getTfIdf(), this.getTfIdf());
    }
}
```

### 关键词类

`Keyword`类存储有关关键词的信息。这些信息包括整个单词以及该单词作为关键词出现在的文档数量。

与`Word`类一样，它实现了`Comparable`接口，因为我们将对关键字数组进行排序以获得最佳关键字：

```java
public class Keyword implements Comparable<Keyword> {
```

然后，我们声明了类的属性并实现了方法来建立和返回其值（这些方法在此处未包括）：

```java
    private String word;
    private int df;
```

最后，我们实现了`compareTo()`方法。我们希望关键词按文档数量从高到低排序：

```java
    @Override
    public int compareTo(Keyword o) {

        return Integer.compare(o.getDf(), this.getDf());
    }
}
```

### Document 类

`Document`类存储有关集合中文档的信息（请记住我们的集合有 100,673 个文档），包括文件名和构成文档的单词集。该单词集通常称为文档的词汇，它以整个单词作为字符串作为键，并以`Word`对象作为值实现为`HashMap`：

```java
public class Document {
    private String fileName;
    private HashMap <String, Word> voc;
```

我们实现了一个构造函数，创建了`HashMap`和方法来获取和设置文件名以及返回文档的词汇（这些方法未包括）。我们还实现了一个方法来在词汇中添加单词。如果单词不存在，则将其添加到其中。如果单词存在于词汇中，则增加单词的`tf`属性。我们使用了`voc`对象的`computeIfAbsent()`方法。该方法如果单词不存在，则将单词插入`HashMap`中，然后使用`addTf()`方法增加`tf`：

```java
    public void addWord(String string) {
        voc.computeIfAbsent(string, k -> new Word(k)).addTf();
    }
}
```

`HashMap`类不是同步的，但我们可以在并发应用程序中使用它，因为它不会在不同任务之间共享。一个`Document`对象只会被一个任务生成，因此我们不会在并发版本中出现由`HashMap`类的使用导致的竞争条件。

### DocumentParser 类

`DocumentParser`类读取文本文件的内容并将其转换为`Document`对象。它将文本拆分为单词并将它们存储在`Document`对象中以生成类的词汇。该类有两个静态方法。第一个是`parse()`方法，它接收一个带有文件路径的字符串并返回一个`Document`对象。它打开文件并逐行读取，使用`parseLine()`方法将每行转换为一系列单词，并将它们存储到`Document`类中：

```java
public class DocumentParser {

    public static Document parse(String path) {
        Document ret = new Document();
        Path file = Paths.get(path);
        ret.setFileName(file.toString());

        try (BufferedReader reader = Files.newBufferedReader(file)) {
            for(String line : Files.readAllLines(file)) {
                parseLine(line, ret);
            }
        } catch (IOException x) {
            x.printStackTrace();
        }
        return ret;

    }
```

`parseLine()`方法接收要解析的行和`Document`对象以存储单词作为参数。

首先，使用`Normalizer`类删除行的重音符号，并将其转换为小写：

```java
    private static void parseLine(String line, Document ret) {

        // Clean string
        line = Normalizer.normalize(line, Normalizer.Form.NFKD);
        line = line.replaceAll("[^\\p{ASCII}]", "");
        line = line.toLowerCase();
```

然后，我们使用`StringTokenizer`类将行拆分为单词，并将这些单词添加到`Document`对象中：

```java
    private static void parseLine(String line, Document ret) {

        // Clean string
        line = Normalizer.normalize(line, Normalizer.Form.NFKD);
        line = line.replaceAll("[^\\p{ASCII}]", "");
        line = line.toLowerCase();

        // Tokenizer

        for(String w: line.split("\\W+")) {
              ret.addWord(w);
        }
    }

}
```

## 串行版本

我们在`SerialKeywordExtraction`类中实现了关键字算法的串行版本。它定义了您将执行以测试算法的`main()`方法。

第一步是声明以下必要的内部变量来执行算法：

+   两个`Date`对象，用于测量执行时间

+   一个字符串，用于存储包含文档集合的目录的名称

+   一个`File`对象数组，用于存储文档集合中的文件

+   一个`HashMap`，用于存储文档集合的全局词汇

+   一个`HashMap`，用于存储关键字

+   两个`int`值，用于测量执行的统计数据

以下包括这些变量的声明：

```java
public class SerialKeywordExtraction {

    public static void main(String[] args) {

        Date start, end;

        File source = new File("data");
        File[] files = source.listFiles();
        HashMap<String, Word> globalVoc = new HashMap<>();
        HashMap<String, Integer> globalKeywords = new HashMap<>();
        int totalCalls = 0;
        int numDocuments = 0;

        start = new Date();
```

然后，我们已经包含了算法的第一阶段。我们使用`DocumentParser`类的`parse()`方法解析所有文档。该方法返回一个包含该文档词汇的`Document`对象。我们使用`HashMap`类的`merge()`方法将文档词汇添加到全局词汇中。如果单词不存在，则将其插入`HashMap`中。如果单词存在，则合并两个单词对象，求和`Tf`和`Df`属性：

```java
        if(files == null) {
            System.err.println("Unable to read the 'data' folder");
            return;
        }
        for (File file : files) {

            if (file.getName().endsWith(".txt")) {
                Document doc = DocumentParser.parse (file.getAbsolutePath());
                for (Word word : doc.getVoc().values()) {
                    globalVoc.merge(word.getWord(), word, Word::merge);
                }
                numDocuments++;
            }
        }
        System.out.println("Corpus: " + numDocuments + " documents.");
```

在这个阶段之后，`globalVocHashMap`类包含了文档集合中所有单词及其全局 TF（单词在集合中出现的总次数）和 DF。

然后，我们包括了算法的第二阶段。我们将使用 TF-IDF 度量来计算每个文档的关键词，正如我们之前解释的那样。我们必须再次解析每个文档以生成其词汇表。我们必须这样做，因为我们无法将由 100,673 个文档组成的文档集合的词汇表存储在内存中。如果您使用的是较小的文档集合，可以尝试仅解析一次文档并将所有文档的词汇表存储在内存中，但在我们的情况下，这是不可能的。因此，我们再次解析所有文档，并且对于每个单词，我们使用存储在`globalVoc`中的值来更新`Df`属性。我们还构建了一个包含文档中所有单词的数组：

```java
        for (File file : files) {
            if (file.getName().endsWith(".txt")) {
                Document doc = DocumentParser.parse(file.getAbsolutePath());
                List<Word> keywords = new ArrayList<>( doc.getVoc().values());

                int index = 0;
                for (Word word : keywords) {
                      Word globalWord = globalVoc.get(word.getWord());
                      word.setDf(globalWord.getDf(), numDocuments);
                }
```

现在，我们有了关键词列表，其中包含文档中所有单词的 TF-IDF 计算结果。我们使用`Collections`类的`sort()`方法对列表进行排序，将 TF-IDF 值较高的单词排在第一位。然后我们获取该列表的前 10 个单词，并使用`addKeyword()`方法将它们存储在`globalKeywordsHashMap`中。

选择前 10 个单词没有特殊原因。您可以尝试其他选项，比如单词的百分比或 TF-IDF 值的最小值，并观察它们的行为：

```java
                Collections.sort(keywords);

                int counter = 0;

                for (Word word : keywords) {
                      addKeyword(globalKeywords, word.getWord());
                      totalCalls++;
                }
            }
        }
```

最后，我们包括了算法的第三阶段。我们将`globalKeywordsHashMap`转换为`Keyword`对象的列表，使用`Collections`类的`sort()`方法对该数组进行排序，获取 DF 值较高的关键词并将其写入控制台的前 100 个单词。

参考以下代码：

```java
        List<Keyword> orderedGlobalKeywords = new ArrayList<>();
        for (Entry<String, Integer> entry : globalKeywords.entrySet()) {
          Keyword keyword = new Keyword();
          keyword.setWord(entry.getKey());
          keyword.setDf(entry.getValue());
          orderedGlobalKeywords.add(keyword);
        }

        Collections.sort(orderedGlobalKeywords);

        if (orderedGlobalKeywords.size() > 100) {
            orderedGlobalKeywords = orderedGlobalKeywords.subList(0, 100);
        }
        for (Keyword keyword : orderedGlobalKeywords) {
            System.out.println(keyword.getWord() + ": " + keyword.getDf());
        }
```

与第二阶段一样，选择前 100 个单词没有特殊原因。如果您愿意，可以尝试其他选项。

在主方法结束时，我们在控制台中写入执行时间和其他统计数据：

```java
        end = new Date();
        System.out.println("Execution Time: " + (end.getTime() - start.getTime()));
        System.out.println("Vocabulary Size: " + globalVoc.size());
        System.out.println("Keyword Size: " + globalKeywords.size());
        System.out.println("Number of Documents: " + numDocuments);
        System.out.println("Total calls: " + totalCalls);

    }
```

`SerialKeywordExtraction`类还包括`addKeyword()`方法，用于更新`globalKeywordsHashMap`类中关键词的信息。如果单词存在，该类会更新其 DF；如果单词不存在，则插入它。

```java
    private static void addKeyword(Map<String, Integer> globalKeywords, String word) {
        globalKeywords.merge(word, 1, Integer::sum);
    }

}
```

## 并发版本

为了实现这个示例的并发版本，我们使用了两个不同的类，如下所示：

+   `KeywordExtractionTasks`类实现了以并发方式计算关键词的任务。我们将以`Thread`对象的形式执行这些任务，因此这个类实现了`Runnable`接口。

+   `ConcurrentKeywordExtraction`类提供了`main()`方法来执行算法，并创建、启动和等待任务完成。

让我们详细看看这些类。

### 关键词提取任务类

正如我们之前提到的，这个类实现了计算最终关键词列表的任务。它实现了`Runnable`接口，因此我们可以将其作为`Thread`执行，并且在内部使用一些属性，其中大部分属性在所有任务之间是共享的：

+   **两个 ConcurrentHashMap 对象用于存储全局词汇表和全局关键词**：我们使用`ConcurrentHashMap`，因为这些对象将由所有任务更新，所以我们必须使用并发数据结构来避免竞争条件。

+   **两个 ConcurrentLinkedDeque 的 File 对象，用于存储构成文档集合的文件列表**：我们使用 `ConcurrentLinkedDeque` 类，因为所有任务都将同时提取（获取和删除）列表的元素，所以我们必须使用并发数据结构来避免竞争条件。如果我们使用普通的 `List`，同一个 `File` 可能会被不同的任务解析两次。我们有两个 `ConcurrentLinkedDeque`，因为我们必须两次解析文档集合。正如我们之前提到的，我们从数据结构中提取 `File` 对象来解析文档集合，因此，当我们解析完集合时，数据结构将为空。

+   **一个 Phaser 对象来控制任务的执行**：正如我们之前解释的那样，我们的关键词提取算法是在三个阶段中执行的。在所有任务完成前，没有一个任务会进入下一个阶段。我们使用 `Phaser` 对象来控制这一点。如果我们不控制这一点，我们将得到不一致的结果。

+   **最终步骤必须由一个线程执行**：我们将使用布尔值区分一个主任务和其他任务。这些主任务将执行最终阶段。

+   **集合中的文档总数**：我们需要这个值来计算 TF-IDF 度量。

我们已经包括了一个构造函数来初始化所有这些属性：

```java
public class KeywordExtractionTask implements Runnable {

    private ConcurrentHashMap<String, Word> globalVoc;
    private ConcurrentHashMap<String, Integer> globalKeywords;

    private ConcurrentLinkedDeque<File> concurrentFileListPhase1;
    private ConcurrentLinkedDeque<File> concurrentFileListPhase2;

    private Phaser phaser;

    private String name;
    private boolean main;

    private int parsedDocuments;
    private int numDocuments;

    public KeywordExtractionTask(
            ConcurrentLinkedDeque<File> concurrentFileListPhase1,
            ConcurrentLinkedDeque<File> concurrentFileListPhase2,
            Phaser phaser, ConcurrentHashMap<String, Word> globalVoc,
            ConcurrentHashMap<String, Integer> globalKeywords,
            int numDocuments, String name, boolean main) {
        this.concurrentFileListPhase1 = concurrentFileListPhase1;
        this.concurrentFileListPhase2 = concurrentFileListPhase2;
        this.globalVoc = globalVoc;
        this.globalKeywords = globalKeywords;
        this.phaser = phaser;
        this.main = main;
        this.name = name;
        this.numDocuments = numDocuments;
    }
```

`run()` 方法实现了算法的三个阶段。首先，我们调用 phaser 的 `arriveAndAwaitAdvance()` 方法等待其他任务的创建。所有任务将在同一时刻开始执行。然后，就像我们在算法的串行版本中解释的那样，我们解析所有文档，并使用所有单词和它们的全局 TF 和 DF 值构建 `globalVocConcurrentHashMap` 类。为了完成第一阶段，我们再次调用 `arriveAndAwaitAdvance()` 方法，等待其他任务在执行第二阶段之前的最终化：

```java
    @Override
    public void run() {
        File file;

        // Phase 1
        phaser.arriveAndAwaitAdvance();
        System.out.println(name + ": Phase 1");
        while ((file = concurrentFileListPhase1.poll()) != null) {
            Document doc = DocumentParser.parse(file.getAbsolutePath());
            for (Word word : doc.getVoc().values()) {
                globalVoc.merge(word.getWord(), word, Word::merge);
            }
            parsedDocuments++;
        }

        System.out.println(name + ": " + parsedDocuments + " parsed.");
        phaser.arriveAndAwaitAdvance();
```

如您所见，为了获取要处理的 `File` 对象，我们使用 `ConcurrentLinkedDeque` 类的 `poll()` 方法。这个方法*检索并删除*`Deque`的第一个元素，所以下一个任务将获得一个不同的文件进行解析，不会有文件被解析两次。

第二阶段计算 `globalKeywords` 结构，就像我们在算法的串行版本中解释的那样。首先，计算每个文档的最佳 10 个关键词，然后将它们插入 `ConcurrentHashMap` 类。代码与串行版本相同，只是将串行数据结构更改为并发数据结构：

```java
        // Phase 2
        System.out.println(name + ": Phase 2");
        while ((file = concurrentFileListPhase2.poll()) != null) {

            Document doc = DocumentParser.parse(file.getAbsolutePath());
            List<Word> keywords = new ArrayList<>(doc.getVoc().values());

            for (Word word : keywords) {
              Word globalWord = globalVoc.get(word.getWord());
              word.setDf(globalWord.getDf(), numDocuments);
            }
            Collections.sort(keywords);

            if(keywords.size() > 10) keywords = keywords.subList(0, 10);
            for (Word word : keywords) {
              addKeyword(globalKeywords, word.getWord());
            }
        }
        System.out.println(name + ": " + parsedDocuments + " parsed.");
```

最终阶段对于主任务和其他任务是不同的。主任务使用 `Phaser` 类的 `arriveAndAwaitAdvance()` 方法等待所有任务的第二阶段最终化，然后在控制台中写入整个集合中最佳的 100 个关键词。最后，它使用 `arriveAndDeregister()` 方法从 phaser 中注销。

其他任务使用 `arriveAndDeregister()` 方法标记第二阶段的最终化，从 phaser 中注销，并完成它们的执行。

当所有任务都完成了他们的工作，它们都从 phaser 中注销了自己。phaser 将没有任何 parties，并且进入终止状态。

```java
        if (main) {
            phaser.arriveAndAwaitAdvance();

            Iterator<Entry<String, Integer>> iterator = globalKeywords.entrySet().iterator();
            Keyword orderedGlobalKeywords[] = new Keyword[globalKeywords.size()];
            int index = 0;
            while (iterator.hasNext()) {
                Entry<String, AtomicInteger> entry = iterator.next();
                Keyword keyword = new Keyword();
                keyword.setWord(entry.getKey());
                keyword.setDf(entry.getValue().get());
                orderedGlobalKeywords[index] = keyword;
                index++;
            }

            System.out.println("Keyword Size: " + orderedGlobalKeywords.length);

            Arrays.parallelSort(orderedGlobalKeywords);
            int counter = 0;
            for (int i = 0; i < orderedGlobalKeywords.length; i++){

                Keyword keyword = orderedGlobalKeywords[i];
                System.out.println(keyword.getWord() + ": " + keyword.getDf());
                counter++;
                if (counter == 100) {
                    break;
                }
            }
        }
        phaser.arriveAndDeregister();

        System.out.println("Thread " + name + " has finished.");
    }
```

### ConcurrentKeywordExtraction 类

`ConcurrentKeywordExtraction` 类初始化了共享对象，创建了任务，执行它们，并等待它们的最终化。它实现了一个 `main()` 方法，可以接收一个可选参数。默认情况下，我们根据 `Runtime` 类的 `availableProcessors()` 方法确定任务的数量，该方法返回 **Java 虚拟机** (**JVM**) 可用的硬件线程数。如果我们收到一个参数，我们将其转换为整数，并将其用作可用处理器数量的乘数，以确定我们将创建的任务数量。

首先，我们初始化所有必要的数据结构和参数。为了填充两个`ConcurrentLinkedDeque`结构，我们使用`File`类的`listFiles()`方法来获取以`txt`后缀结尾的文件的`File`对象数组。

我们还使用不带参数的构造函数创建`Phaser`对象，因此所有任务必须显式地在屏障中注册自己。参考以下代码：

```java
public class ConcurrentKeywordExtraction {

    public static void main(String[] args) {

        Date start, end;

        ConcurrentHashMap<String, Word> globalVoc = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> globalKeywords = new ConcurrentHashMap<>();

        start = new Date();
        File source = new File("data");

        File[] files = source.listFiles(f -> f.getName().endsWith(".txt"));
        if (files == null) {
            System.err.println("The 'data' folder not found!");
            return;
        }
        ConcurrentLinkedDeque<File> concurrentFileListPhase1 = new ConcurrentLinkedDeque<>(Arrays.asList(files));
        ConcurrentLinkedDeque<File> concurrentFileListPhase2 = new ConcurrentLinkedDeque<>(Arrays.asList(files));

        int numDocuments = files.length();
        int factor = 1;
        if (args.length > 0) {
            factor = Integer.valueOf(args[0]);
        }

        int numTasks = factor * Runtime.getRuntime().availableProcessors();
        Phaser phaser = new Phaser();

        Thread[] threads = new Thread[numTasks];
        KeywordExtractionTask[] tasks = new KeywordExtractionTask[numTasks];
```

然后，我们使用`true`作为主参数创建第一个任务，其余使用`false`作为主参数。在创建每个任务之后，我们使用`Phaser`类的`register()`方法来注册新的参与者到屏障中，如下所示：

```java
        for (int i = 0; i < numTasks; i++) {
            tasks[i] = new KeywordExtractionTask(concurrentFileListPhase1, concurrentFileListPhase2, phaser, globalVoc, globalKeywords, concurrentFileListPhase1.size(), "Task" + i, i==0);
            phaser.register();
            System.out.println(phaser.getRegisteredParties() + " tasks arrived to the Phaser.");
        }
```

然后，我们创建并启动运行任务的线程对象，并等待其完成：

```java
        for (int i = 0; i < numTasks; i++) {
            threads[i] = new Thread(tasks[i]);
            threads[i].start();
        }

        for (int i = 0; i < numTasks; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
```

最后，我们在控制台中写入有关执行的一些统计信息，包括执行时间：

```java
        System.out.println("Is Terminated: " + phaser.isTerminated());

        end = new Date();
        System.out.println("Execution Time: " + (end.getTime() - start.getTime()));
        System.out.println("Vocabulary Size: " + globalVoc.size());
        System.out.println("Number of Documents: " + numDocuments);

    }

}
```

## 比较两种解决方案

让我们比较我们的关键词提取 100,673 个文档的串行和并发版本。我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行示例，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的平均执行时间。

| 算法 | 因子 | 执行时间（秒） |
| --- | --- | --- |
| **串行** | N/A | 194.45 |
| **并发** | 1 | 64.52 |
| 2 | 65.55 |
| 3 | 68,23 |

我们可以得出以下结论：

+   算法的并发版本提高了串行版本的性能。

+   如果我们使用的任务数量超过了可用的硬件线程数量，我们不会得到更好的结果。只会稍微差一点，因为额外的同步工作必须由屏障执行。

我们比较并发和串行版本的算法，使用以下公式计算加速比：

![比较两种解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00015.jpeg)

# 第二个例子 - 遗传算法

**遗传算法**是基于自然选择原理的自适应启发式搜索算法，用于生成**优化**和**搜索问题**的良好解决方案。它们处理问题的可能解决方案，称为**个体**或**表型**。每个个体都有一个由一组属性组成的表示，称为**染色体**。通常，个体由一系列位表示，但你可以选择最适合你问题的表示形式。

你还需要一个确定解决方案好坏的函数，称为**适应度函数**。遗传算法的主要目标是找到最大化或最小化该函数的解决方案。

遗传算法从一组可能的问题解决方案开始。这组可能的解决方案被称为种群。你可以随机生成这个初始集，或者使用某种启发式函数来获得更好的初始解决方案。

一旦你有了初始种群，你就开始一个迭代过程，包括三个阶段。该迭代过程的每一步被称为一代。每一代的阶段包括：

+   **选择**: 你选择种群中更好的个体。这些个体在适应度函数中具有更好的值。

+   **交叉**: 你交叉选择在上一步中选定的个体，以生成新的个体，形成新的一代。这个操作需要两个个体，并生成两个新的个体。这个操作的实现取决于你想要解决的问题以及你选择的个体的表示。

+   **突变**：您可以应用突变运算符来改变个体的值。通常，您会将该操作应用于非常少量的个体。虽然突变是找到良好解决方案的一个非常重要的操作，但我们不会在简化示例中应用它。

您重复这三个操作，直到满足您的完成标准。这些完成标准可以是：

+   固定数量的世代

+   预定义的适应度函数值

+   找到符合预定义标准的解决方案

+   时间限制

+   手动停止

通常，您会在种群之外存储您在整个过程中找到的最佳个体。这个个体将是算法提出的解决方案，通常情况下，它会是一个更好的解决方案，因为我们会生成新的世代。

在本节中，我们将实现一个遗传算法来解决著名的**旅行推销员问题**（**TSP**）。在这个问题中，您有一组城市和它们之间的距离，您希望找到一条最佳路线，穿过所有城市并最小化旅行的总距离。与其他示例一样，我们实现了一个串行版本和一个并发版本，使用了`Phaser`类。应用于 TSP 问题的遗传算法的主要特征是：

+   **个体**：个体表示城市的遍历顺序。

+   **交叉**：在交叉操作之后，您必须创建有效的解决方案。您必须只访问每个城市一次。

+   **适应度函数**：算法的主要目标是最小化穿过城市的总距离。

+   **完成标准**：我们将执行预定义数量的世代算法。

例如，您可以有一个包含四个城市的距离矩阵，如下表所示：

|   | 城市 1 | 城市 2 | 城市 3 | 城市 4 |
| --- | --- | --- | --- | --- |
| **城市 1** | 0 | 11 | 6 | 9 |
| **城市 2** | 7 | 0 | 8 | 2 |
| **城市 3** | 7 | 3 | 0 | 3 |
| **城市 4** | 10 | 9 | 4 | 0 |

这意味着城市 2 和城市 1 之间的距离是 7，但城市 1 和城市 2 之间的距离是 11。一个个体可以是（2,4,3,1），其适应度函数是 2 和 4 之间的距离、4 和 3 之间的距离、3 和 1 之间的距离以及 1 和 2 之间的距离的总和，即 2+4+7+11=24。

如果您想在个体（1,2,3,4）和（1,3,2,4）之间进行交叉，您不能生成个体（1,2,2,4），因为您访问了城市 2 两次。您可以生成个体（1,2,4,3）和（1,3,4,2）。

为了测试算法，我们使用了两个**城市距离数据集**的例子（[`people.sc.fsu.edu/~jburkardt/datasets/cities/cities.html`](http://people.sc.fsu.edu/~jburkardt/datasets/cities/cities.html)），分别为 15 个城市（`lau15_dist`）和 57 个城市（`kn57_dist`）。

## 常见类

两个版本都使用以下三个常见类：

+   `DataLoader`类从文件加载距离矩阵。我们不在这里包括该类的代码。它有一个静态方法，接收文件名并返回一个`int[][]`矩阵，其中存储了城市之间的距离。距离存储在 csv 文件中（我们对原始格式进行了一些小的转换），因此很容易进行转换。

+   `Individual`类存储种群中个体的信息（问题的可能解决方案）。为了表示每个个体，我们选择了一个整数值数组，它存储您访问不同城市的顺序。

+   `GeneticOperators`类实现了种群或个体的交叉、选择和评估。

让我们看看`Individual`和`GeneticOperators`类的详细信息。

### 个体类

这个类存储了我们 TSP 问题的每个可能解。我们称每个可能解为一个个体，它的表示是染色体。在我们的情况下，我们将每个可能解表示为一个整数数组。该数组包含推销员访问城市的顺序。这个类还有一个整数值来存储适应函数的结果。我们有以下代码：

```java
public class Individual implements Comparable<Individual> {
    private Integer[] chromosomes;
    private int value;
```

我们包括了两个构造函数。第一个接收你必须访问的城市数量，然后创建一个空数组。另一个接收一个`Individual`对象，并将其染色体复制如下：

```java
    public Individual(int size) {
        chromosomes=new Integer[size];
    }

    public Individual(Individual other) {
        chromosomes = other.getChromosomes().clone();

    }
```

我们还实现了`compareTo()`方法，使用适应函数的结果来比较两个个体：

```java
    @Override
    public int compareTo(Individual o) {
          return Integer.compare(this.getValue(), o.getValue());
    }
```

最后，我们已经包括了获取和设置属性值的方法。

### 遗传算法操作类

这是一个复杂的类，因为它实现了遗传算法的内部逻辑。它提供了初始化、选择、交叉和评估操作的方法，就像在本节开头介绍的那样。我们只描述了这个类提供的方法，而没有描述它们是如何实现的，以避免不必要的复杂性。你可以获取示例的源代码来分析这些方法的实现。

这个类提供的方法有：

+   `initialize(int numberOfIndividuals, int size)`: 这将创建一个新的种群。种群的个体数量将由`numberOfIndividuals`参数确定。染色体的数量（在我们的情况下是城市）将由大小参数确定。它返回一个`Individual`对象的数组。它使用初始化方法(`Integer[]`)来初始化每个个体。

+   `initialize(Integer[] chromosomes)`: 它以随机方式初始化个体的染色体。它生成有效的个体（你必须只访问每个城市一次）。

+   `selection(Individual[] population)`: 这个方法实现了选择操作，以获取种群中最好的个体。它以一个数组的形式返回这些个体。数组的大小将是种群大小的一半。你可以测试其他标准来确定选择的个体数量。我们选择适应函数最好的个体。

+   `crossover(Individual[] selected, int numberOfIndividuals, int size)`: 这个方法接收上一代选择的个体作为参数，并使用交叉操作生成下一代的种群。下一代的个体数量将由同名的参数确定。每个个体的染色体数量将由大小参数确定。它使用交叉方法(`Individual`, `Individual`, `Individual`, `Individual`)从两个选择的个体生成两个新的个体。

+   `crossover(Individual parent1, Individual parent2, Individual individual1, Individual individual2)`: 这个方法执行交叉操作，以获取`parent1`和`parent2`个体生成下一代的`individual1`和`individual2`个体。

+   `evaluate(Individual[] population, int [][] distanceMatrix)`: 这将使用接收的距离矩阵对种群中的所有个体应用适应函数。最后，它将种群从最佳到最差的解进行排序。它使用评估方法(`Individual`, `int[][]`)来评估每个个体。

+   `evaluate(Individual individual, int[][] distanceMatrix)`: 这将适用于一个个体的适应函数。

有了这个类和它的方法，你就有了实现解决 TSP 问题的遗传算法所需的一切。

## 串行版本

我们使用以下两个类实现了算法的串行版本：

+   实现算法的`SerialGeneticAlgorithm`类

+   `SerialMain`类执行算法，并测量执行时间

让我们详细分析这两个类。

### SerialGeneticAlgorithm 类

这个类实现了我们遗传算法的串行版本。在内部，它使用以下四个属性：

+   包含所有城市之间距离的距离矩阵

+   代的数量

+   种群中的个体数

+   每个个体中的染色体数

该类还有一个构造函数来初始化所有属性：

```java
    private int[][] distanceMatrix;

    private int numberOfGenerations;
    private int numberOfIndividuals;

    private int size;

    public SerialGeneticAlgorithm(int[][] distanceMatrix,
            int numberOfGenerations, int numberOfIndividuals) {
        this.distanceMatrix = distanceMatrix;
        this.numberOfGenerations = numberOfGenerations;
        this.numberOfIndividuals = numberOfIndividuals;
        size = distanceMatrix.length;
    }
```

该类的主要方法是`calculate()`方法。首先，使用`initialize()`方法创建初始种群。然后，评估初始种群，并将其最佳个体作为算法的第一个解决方案：

```java
    public Individual calculate() {
        Individual best;

        Individual[] population = GeneticOperators.initialize(
                numberOfIndividuals, size);
        GeneticOperators.evaluate(population, distanceMatrix);

        best = population[0];
```

然后，它执行一个由`numberOfGenerations`属性确定的循环。在每个周期中，它使用`selection()`方法获取选定的个体，使用`crossover()`方法计算下一代，评估这个新一代，并且如果新一代的最佳解决方案比到目前为止的最佳个体更好，我们就替换它。当循环结束时，我们将最佳个体作为算法提出的解决方案返回：

```java
        for (int i = 1; i <= numberOfGenerations; i++) {
            Individual[] selected = GeneticOperators.selection(population);
            population = GeneticOperators.crossover(selected, numberOfIndividuals, size);
            GeneticOperators.evaluate(population, distanceMatrix);
            if (population[0].getValue() < best.getValue()) {
                best = population[0];
            }

        }

        return best;
    }
```

### SerialMain 类

该类为本节中使用的两个数据集执行遗传算法——包含 15 个城市的`lau15`和包含 57 个城市的`kn57`。

`main()`方法必须接收两个参数。第一个是我们想要创建的代数，第二个参数是我们想要每一代中拥有的个体数：

```java
public class SerialMain {

    public static void main(String[] args) {

        Date start, end;

        int generations = Integer.valueOf(args[0]);
        int individuals = Integer.valueOf(args[1]);
```

对于每个示例，我们使用`DataLoader`类的`load()`方法加载距离矩阵，创建`SerialGeneticAlgorith`对象，执行`calculate()`方法并测量执行时间，并将执行时间和结果写入控制台：

```java
    for (String name : new String[] { "lau15_dist", "kn57_dist" }) {
        int[][] distanceMatrix = DataLoader.load(Paths.get("data", name + ".txt"));
        SerialGeneticAlgorithm serialGeneticAlgorithm = new SerialGeneticAlgorithm(distanceMatrix, generations, individuals);
            start = new Date();
            Individual result = serialGeneticAlgorithm.calculate();
            end = new Date();
        System.out.println ("=======================================");
        System.out.println("Example:"+name);
        System.out.println("Generations: " + generations);
        System.out.println("Population: " + individuals);
        System.out.println("Execution Time: " + (end.getTime() - start.getTime()));
        System.out.println("Best Individual: " + result);
        System.out.println("Total Distance: " + result.getValue());
        System.out.println ("=======================================");
    }
```

## 并发版本

我们已经实现了遗传算法的并发版本不同的类：

+   `SharedData`类存储所有任务之间共享的对象

+   `GeneticPhaser`类扩展了`Phaser`类，并覆盖了它的`onAdvance()`方法，以在所有任务完成一个阶段时执行代码

+   `ConcurrentGeneticTask`类实现了遗传算法阶段的任务

+   `ConcurrentGeneticAlgorithm`类将使用前面的类实现遗传算法的并发版本

+   `ConcurrentMain`类将在我们的两个数据集中测试遗传算法的并发版本

在内部，`ConcurrentGeneticTask`类将执行三个阶段。第一个阶段是选择阶段，只有一个任务执行。第二个阶段是交叉阶段，所有任务将使用选定的个体构建新一代，最后一个阶段是评估阶段，所有任务将评估新一代的个体。

让我们详细看看这些类中的每一个。

### SharedData 类

正如我们之前提到的，这个类包含了所有任务共享的对象。这包括以下内容：

+   种群数组，包含一代中的所有个体。

+   选定的数组与选定的个体。

+   一个名为`index`的原子整数。这是唯一的线程安全对象，用于知道任务必须生成或处理的个体的索引。

+   所有代中的最佳个体将作为算法的解决方案返回。

+   包含城市之间距离的距离矩阵。

所有这些对象将被所有线程共享，但我们只需要使用一个并发数据结构。这是唯一一个有效被所有任务共享的属性。其余的对象将只被读取（距离矩阵），或者每个任务将访问对象的不同部分（种群和选定的数组），因此我们不需要使用并发数据结构或同步机制来避免竞争条件：

```java
public class SharedData {

    private Individual[] population;
    private Individual selected[];
    private AtomicInteger index;
    private Individual best;
    private int[][] distanceMatrix;
}
```

该类还包括获取器和设置器，用于获取和建立这些属性的值。

### GeneticPhaser 类

我们需要在任务的阶段变化时执行代码，因此我们必须实现自己的阶段器并重写`onAdvance()`方法，该方法在所有参与方完成一个阶段之后执行，然后开始执行下一个阶段。`GeneticPhaser`类实现了这个阶段器。它存储`SharedData`对象以便与其一起工作，并将其作为构造函数的参数接收：

```java
public class GeneticPhaser extends Phaser {

    private SharedData data;

    public GeneticPhaser(int parties, SharedData data) {
        super(parties);
        this.data=data;
    }
```

`onAdvance()`方法将接收阶段器的阶段号和注册方的数量作为参数。阶段器内部将阶段号作为整数存储，随着每次阶段变化而递增。相反，我们的算法只有三个阶段，将被执行很多次。我们必须将阶段器的阶段号转换为遗传算法的阶段号，以了解任务是否将执行选择、交叉或评估阶段。为此，我们计算阶段器阶段号除以三的余数，如下所示：

```java
    protected boolean onAdvance(int phase, int registeredParties) {
        int realPhase=phase%3;
        if (registeredParties>0) {
            switch (realPhase) {
            case 0:
            case 1:
                data.getIndex().set(0);
                break;
            case 2:
                Arrays.sort(data.getPopulation());
                if (data.getPopulation()[0].getValue() < data.getBest().getValue()) {
                    data.setBest(data.getPopulation()[0]);
                }
                break;
            }
            return false;
        }
        return true;
    }
```

如果余数为零，则任务已经完成了选择阶段，并将执行交叉阶段。我们用值零初始化索引对象。

如果余数为一，则任务已经完成了交叉阶段，并将执行评估阶段。我们用值零初始化索引对象。

最后，如果余数为二，则任务已经完成了评估阶段，并将重新开始选择阶段。我们根据适应度函数对种群进行排序，并在必要时更新最佳个体。

请注意，这个方法只会由一个线程执行，与任务无关。它将在任务的线程中执行，这个任务是最后完成上一个阶段的（在`arriveAndAwaitAdvance()`调用中）。其余的任务将处于睡眠状态，等待阶段器。

### ConcurrentGeneticTask 类

这个类实现了协作执行遗传算法的任务。它们执行算法的三个阶段（选择、交叉和评估）。选择阶段将只由一个任务执行（我们称之为主任务），而其余的阶段将由所有任务执行。

在内部，它使用了四个属性：

+   一个`GeneticPhaser`对象，用于在每个阶段结束时同步任务

+   一个`SharedData`对象来访问共享数据

+   它必须计算的代数

+   指示是否为主任务的布尔标志

所有这些属性都在类的构造函数中初始化：

```java
public class ConcurrentGeneticTask implements Runnable {
    private GeneticPhaser phaser;
    private SharedData data;
    private int numberOfGenerations;
    private boolean main;

    public ConcurrentGeneticTask(GeneticPhaser phaser, int numberOfGenerations, boolean main) {
        this.phaser = phaser;
        this.numberOfGenerations = numberOfGenerations;
        this.main = main;
        this.data = phaser.getData();
    }
```

`run()`方法实现了遗传算法的逻辑。它有一个循环来生成指定的代数。正如我们之前提到的，只有主任务才会执行选择阶段。其余的任务将使用`arriveAndAwaitAdvance()`方法等待此阶段的完成。参考以下代码：

```java
    @Override
    public void run() {

        Random rm = new Random(System.nanoTime()); 
		for (int i = 0; i < numberOfGenerations; i++) {
            if (main) {
                data.setSelected(GeneticOperators.selection(data
                        .getPopulation()));
            }
            phaser.arriveAndAwaitAdvance();
```

第二阶段是交叉阶段。我们使用`SharedData`类中存储的`AtomicInteger`变量索引来获取每个任务将计算的种群数组中的下一个位置。正如我们之前提到的，交叉操作会生成两个新个体，因此每个任务首先在种群数组中保留两个位置。为此，我们使用`getAndAdd(2)`方法，它返回变量的实际值并将其值增加两个单位。它是一个原子变量，因此我们不需要使用任何同步机制。这是原子变量固有的。参考以下代码：

```java
            // Crossover
            int individualIndex;
            do {
                individualIndex = data.getIndex().getAndAdd(2);
                if (individualIndex < data.getPopulation().length) {
                    int secondIndividual = individualIndex++;

                    int p1Index = rm.nextInt (data.getSelected().length);
                    int p2Index;
                    do {
                        p2Index = rm.nextInt (data.getSelected().length);
                    } while (p1Index == p2Index);

                    Individual parent1 = data.getSelected() [p1Index];
                    Individual parent2 = data.getSelected() [p2Index];
                    Individual individual1 = data.getPopulation() [individualIndex];
                    Individual individual2 = data.getPopulation() [secondIndividual];

                    GeneticOperators.crossover(parent1, parent2, individual1, individual2);
                }
            } while (individualIndex < data.getPopulation().length);
            phaser.arriveAndAwaitAdvance();
```

当新种群的所有个体都生成时，任务使用`arriveAndAwaitAdvance()`方法来同步阶段的结束。

最后一个阶段是评估阶段。我们再次使用`AtomicInteger`索引。每个任务都会得到变量的实际值，该值代表种群中个体的位置，并使用`getAndIncrement()`方法递增其值。一旦所有个体都被评估，我们使用`arriveAndAwaitAdvance()`方法来同步这个阶段的结束。请记住，当所有任务都完成了这个阶段时，`GeneticPhaser`类将执行对种群数组的排序，并根据需要更新最佳个体变量，如下所示：

```java
            // Evaluation
            do {
                individualIndex = data.getIndex().getAndIncrement();
                if (individualIndex < data.getPopulation().length) {
                    GeneticOperators.evaluate(data.getPopulation() [individualIndex], data.getDistanceMatrix());
                }
            } while (individualIndex < data.getPopulation().length);
            phaser.arriveAndAwaitAdvance();

        }

        phaser.arriveAndDeregister();
    }
```

最后，当所有代数都被计算时，任务使用`arriveAndDeregister()`方法来指示其执行的结束，因此 phaser 将进入最终状态。

### ConcurrentGeneticAlgorithm 类

这个类是遗传算法的外部接口。在内部，它创建、启动并等待计算不同代数的任务的完成。它使用四个属性：代数的数量、每一代中个体的数量、每个个体的染色体数量和距离矩阵，如下所示：

```java
public class ConcurrentGeneticAlgorithm {

    private int numberOfGenerations;
    private int numberOfIndividuals;
    private int[][] distanceMatrix;
    private int size;

    public ConcurrentGeneticAlgorithm(int[][] distanceMatrix, int numberOfGenerations, int numberOfIndividuals) {
        this.distanceMatrix=distanceMatrix;
        this.numberOfGenerations=numberOfGenerations;
        this.numberOfIndividuals=numberOfIndividuals;
        size=distanceMatrix.length;
    }
```

`calculate()`方法执行遗传算法并返回最佳个体。首先，它使用`initialize()`方法创建初始种群，评估该种群，并创建和初始化一个带有所有必要数据的`SharedData`对象，如下所示：

```java
    public Individual calculate() {

        Individual[] population= GeneticOperators.initialize(numberOfIndividuals,size);
        GeneticOperators.evaluate(population,distanceMatrix);

        SharedData data=new SharedData();
        data.setPopulation(population);
        data.setDistanceMatrix(distanceMatrix);
        data.setBest(population[0]);
```

然后，它创建任务。我们使用计算机的可用硬件线程数，该数由`Runtime`类的`availableProcessors()`方法返回，作为我们将要创建的任务数。我们还创建了一个`GeneticPhaser`对象来同步这些任务的执行，如下所示：

```java
        int numTasks=Runtime.getRuntime().availableProcessors();
        GeneticPhaser phaser=new GeneticPhaser(numTasks,data);

        ConcurrentGeneticTask[] tasks=new ConcurrentGeneticTask[numTasks];
        Thread[] threads=new Thread[numTasks];

        tasks[0]=new ConcurrentGeneticTask(phaser, numberOfGenerations, true);
        for (int i=1; i< numTasks; i++) {
            tasks[i]=new ConcurrentGeneticTask(phaser, numberOfGenerations, false);
        }
```

然后，我们创建`Thread`对象来执行任务，启动它们，并等待它们的完成。最后，我们返回存储在`ShareData`对象中的最佳个体，如下所示：

```java
        for (int i=0; i<numTasks; i++) {
            threads[i]=new Thread(tasks[i]);
            threads[i].start();
        }

        for (int i=0; i<numTasks; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return data.getBest();
    }
}
```

### ConcurrentMain 类

这个类执行了遗传算法，用于本节中使用的两个数据集——有 15 个城市的`lau15`和有 57 个城市的`kn57`。它的代码类似于`SerialMain`类，但是使用`ConcurrentGeneticAlgorithm`代替`SerialGeneticAlgorithm`。

## 比较两种解决方案

现在是时候测试两种解决方案，看看它们哪个性能更好。正如我们之前提到的，我们使用了城市距离数据集（[`people.sc.fsu.edu/~jburkardt/datasets/cities/cities.html`](http://people.sc.fsu.edu/~jburkardt/datasets/cities/cities.html)）中的两个数据集——有 15 个城市的`lau15`和有 57 个城市的`kn57`。我们还测试了不同规模的种群（100、1,000 和 10,000 个个体）和不同代数的数量（10、100 和 1,000）。为了测试算法，我们使用了 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)），它允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的中间执行时间。

### Lau15 数据集

第一个数据集的执行时间（毫秒）为：

|   | 人口 |
| --- | --- |
|   | **100** | **1,000** | **10,000** |
| 代数 | 串行 | 并发 | 串行 | 并发 | 串行 | 并发 |
| **10** | 8.42 | 13.309 | 30.783 | 36.395 | 182.213 | 99.728 |
| **100** | 25.848 | 29.292 | 135.562 | 69.257 | 1488.457 | 688.840 |
| **1,000** | 117.929 | 71.771 | 1134.983 | 420.145 | 11810.518 | 4102.72 |

### Kn57 数据集

第二个数据集的执行时间（毫秒）为：

|   | 人口 |
| --- | --- |
|   | **100** | **1,000** | **10,000** |
| **Generations** | **Serial** | **Concurrent** | **Serial** | **Concurrent** | **Serial** | **Concurrent** |
| **10** | 19.205 | 22.246 | 80.509 | 63.370 | 758.235 | 300.669 |
| **100** | 75.129 | 63.815 | 680.548 | 225.393 | 7406.392 | 2561.219 |
| **1,000** | 676.390 | 243.572 | 6796.780 | 2159.124 | 75315.885 | 26825.115 |

### 结论

算法的行为与两个数据集相似。您可以看到，当个体数量和世代数量较少时，算法的串行版本具有更好的执行时间，但是当个体数量或世代数量增加时，并发版本具有更好的吞吐量。例如，对于包含 1,000 代和 10,000 个体的`kn57`数据集，加速比为：

![结论](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00016.jpeg)

# 摘要

在本章中，我们解释了 Java 并发 API 提供的最强大的同步机制之一：phaser。其主要目标是在执行分阶段算法的任务之间提供同步。在其余任务完成前，没有一个任务可以开始执行下一个阶段。

Phaser 必须知道有多少任务需要同步。您必须使用构造函数、`bulkRegister()`方法或`register()`方法在 phaser 中注册您的任务。

任务可以以不同的方式与 phaser 同步。最常见的是使用`arriveAndAwaitAdvance()`方法通知 phaser 已经完成一个阶段的执行，并希望继续下一个阶段。此方法将使线程休眠，直到其余任务完成当前阶段。但是还有其他方法可以用来同步您的任务。`arrive()`方法用于通知 phaser 您已经完成当前阶段，但不等待其余任务（使用此方法时要非常小心）。`arriveAndDeregister()`方法用于通知 phaser 您已经完成当前阶段，并且不希望继续在 phaser 中（通常是因为您已经完成了工作）。最后，`awaitAdvance()`方法可用于等待当前阶段的完成。

您可以使用`onAdvance()`方法控制相位变化，并在所有任务完成当前阶段并开始新阶段之前执行代码。此方法在两个阶段的执行之间调用，并接收相位编号和相位中参与者的数量作为参数。您可以扩展`Phaser`类并覆盖此方法以在两个阶段之间执行代码。

Phaser 可以处于两种状态：活动状态，当它正在同步任务时；终止状态，当它完成了其工作时。当所有参与者调用`arriveAndDeregister()`方法或`onAdvance()`方法返回`true`值时（默认情况下，它总是返回`false`），Phaser 将进入终止状态。当`Phaser`类处于终止状态时，它将不再接受新的参与者，并且同步方法将立即返回。

我们使用`Phaser`类来实现两种算法：关键词提取算法和遗传算法。在这两种情况下，我们都得到了与这些算法的串行版本相比的重要吞吐量增加。

在下一章中，您将学习如何使用另一个 Java 并发框架来解决特殊类型的问题。这就是 Fork/Join 框架，它已经被开发出来以并发方式执行那些可以使用分而治之算法解决的问题。它基于具有特殊工作窃取算法的执行程序，以最大化执行程序的性能。


# 第六章：优化分而治之解决方案-Fork/Join 框架

在第二章中，*管理大量线程-执行者*，第三章，*从执行者中获得最大效益*，和第四章，*从任务中获取数据-Callable 和 Future 接口*，您学会了如何使用执行者作为一种机制来提高并发应用程序的性能，执行大量并发任务。Java 7 并发 API 引入了一种特殊类型的执行者，通过 Fork/Join 框架。该框架旨在实现使用分而治之设计范例解决问题的最佳并发解决方案。在本章中，我们将涵盖以下主题：

+   Fork/Join 框架简介

+   第一个示例- k 均值聚类算法

+   第二个示例-数据过滤算法

+   第三个示例-归并排序算法

# Fork/Join 框架简介

在 Java 5 中引入的执行者框架提供了一种执行并发任务的机制，而无需创建、启动和完成线程。该框架使用一个线程池来执行您发送给执行者的任务，并重用它们执行多个任务。这种机制为程序员提供了一些优势，如下所示：

+   编写并发应用程序更容易，因为您不必担心创建线程。

+   更容易控制执行者和应用程序使用的资源。您可以创建一个只使用预定义数量线程的执行者。如果发送更多任务，执行者会将它们存储在队列中，直到有线程可用。

+   执行者通过重用线程减少了线程创建引入的开销。在内部，它管理一个线程池，重用线程执行多个任务。

分而治之算法是一种非常流行的设计技术。使用这种技术解决问题，您将其分解为更小的问题。您以递归方式重复这个过程，直到您要解决的问题足够小，可以直接解决。这种类型的问题可以使用执行者解决，但为了以更有效的方式解决它们，Java 7 并发 API 引入了 Fork/Join 框架。

该框架基于`ForkJoinPool`类，这是一种特殊类型的执行者，两个操作，`fork()`和`join()`方法（及其不同的变体），以及一个名为**工作窃取算法**的内部算法。在本章中，您将学习 Fork/Join 框架的基本特征、限制和组件，实现以下三个示例：

+   应用于一组文档聚类的 k 均值聚类算法

+   一个数据过滤算法，以获取符合某些条件的数据

+   归并排序算法以高效的方式对大量数据进行排序

## Fork/Join 框架的基本特征

正如我们之前提到的，Fork/Join 框架必须用于实现基于分而治之技术的问题的解决方案。您必须将原始问题分解为更小的问题，直到它们足够小，可以直接解决。使用该框架，您将实现主要方法类似于以下内容的任务：

```java
if ( problem.size() > DEFAULT_SIZE) {
    divideTasks();
    executeTask();
    taskResults=joinTasksResult();
    return taskResults;
} else {
    taskResults=solveBasicProblem();
    return taskResults;
}
```

最重要的部分是允许您以高效的方式分割和执行子任务，并获取这些子任务的结果以计算父任务的结果。这个功能由`ForkJoinTask`类提供的两个方法支持，如下所示：

+   `fork()`方法：此方法允许您向 Fork/Join 执行者发送子任务

+   join()方法：此方法允许您等待子任务的完成并返回其结果

这些方法有不同的变体，正如您将在示例中看到的那样。Fork/Join 框架还有另一个关键部分：工作窃取算法，它确定要执行哪些任务。当一个任务正在等待使用 join()方法等待子任务的完成时，执行该任务的线程会从等待的任务池中取出另一个任务并开始执行。这样，Fork/Join 执行器的线程总是通过执行任务来提高应用程序的性能。

Java 8 在 Fork/Join 框架中包含了一个新特性。现在每个 Java 应用程序都有一个名为 common pool 的默认 ForkJoinPool。您可以通过调用 ForkJoinPool.commonPool()静态方法来获取它。您不需要显式创建一个（尽管您可以）。这个默认的 Fork/Join 执行器将默认使用计算机可用处理器确定的线程数。您可以通过更改系统属性 java.util.concurrent.ForkJoinPool.common.parallelism 的值来更改此默认行为。

Java API 的一些特性使用 Fork/Join 框架来实现并发操作。例如，Arrays 类的 parallelSort()方法以并行方式对数组进行排序，以及 Java 8 中引入的并行流（稍后将在第七章和第八章中描述）使用了这个框架。

## Fork/Join 框架的限制

由于 Fork/Join 框架被设计用来解决一种确定类型的问题，因此在使用它来实现您的问题时，您必须考虑一些限制，如下所示：

+   您不打算细分的基本问题不应该太大，但也不应该太小。根据 Java API 文档，它应该在 100 到 10,000 个基本计算步骤之间。

+   您不应该使用阻塞 I/O 操作，比如读取用户输入或等待网络套接字中的数据可用。这样的操作会导致 CPU 核心空闲，降低并行级别，因此您将无法实现完全的性能。

+   您不能在任务中抛出已检查的异常。您必须包含处理它们的代码（例如，包装成未检查的 RuntimeException）。未检查的异常有特殊处理，正如您将在示例中看到的那样。

## Fork/Join 框架的组件

Fork/Join 框架中有五个基本类：

+   ForkJoinPool 类：该类实现了 Executor 和 ExecutorService 接口，它是您要使用来执行 Fork/Join 任务的 Executor 接口。Java 为您提供了一个默认的 ForkJoinPool 对象（名为 common pool），但如果您愿意，您可以使用一些构造函数来创建一个。您可以指定并行级别（最大运行并行线程数）。默认情况下，它使用可用处理器的数量作为并发级别。

+   `ForkJoinTask`类：这是所有 Fork/Join 任务的基本抽象类。它是一个抽象类，提供了`fork()`和`join()`方法以及它们的一些变体。它还实现了`Future`接口，并提供了方法来确定任务是否以正常方式完成，是否被取消，或者是否抛出未检查的异常。`RecursiveTask`、`RecursiveAction`和`CountedCompleter`类提供了`compute()`抽象方法，应该在子类中实现以执行实际的计算。

+   `RecursiveTask`类：这个类扩展了`ForkJoinTask`类。它也是一个抽象类，应该是实现返回结果的 Fork/Join 任务的起点。

+   `RecursiveAction`类：这个类扩展了`ForkJoinTask`类。它也是一个抽象类，应该是实现不返回结果的 Fork/Join 任务的起点。

+   `CountedCompleter`类：这个类扩展了`ForkJoinTask`类。这是 Java 8 API 的一个新特性，应该是实现任务在完成时触发其他任务的起点。

# 第一个例子 - k 均值聚类算法

**k 均值聚类**算法是一种聚类算法，用于将一组未经分类的项目分组到预定义数量的 k 个集群中。在数据挖掘和机器学习领域非常受欢迎，以无监督的方式组织和分类数据。

每个项目通常由一组特征或属性的向量来定义。所有项目具有相同数量的属性。每个集群也由具有相同数量属性的向量来定义，表示所有分类到该集群的项目。这个向量被称为质心。例如，如果项目由数值向量定义，那么集群由分类到该集群的项目的平均值来定义。

基本上，这个算法有四个步骤：

1.  **初始化**：在第一步中，你需要创建代表 K 个集群的初始向量。通常，你会随机初始化这些向量。

1.  **分配**：然后，你将每个项目分类到一个集群中。为了选择集群，你需要计算项目与每个集群之间的距离。你将使用**欧几里得距离**作为距离度量来计算代表项目的向量与代表集群的向量之间的距离。你将把项目分配给距离最短的集群。

1.  **更新**：一旦所有项目被分类，你需要重新计算定义每个集群的向量。正如我们之前提到的，通常计算分类到集群的所有向量的平均值。

1.  **结束**：最后，你要检查是否有任何项目改变了分配的集群。如果有任何改变，你需要再次进行分配步骤。否则，算法结束，你的项目被分类了。

这个算法有以下两个主要限制：

+   如果你对集群的初始向量进行随机初始化，就像我们之前建议的那样，对同一组项目进行两次执行可能会得到不同的结果。

+   集群的数量是预先定义的。选择这个属性不好会导致分类结果不佳。

尽管如此，该算法非常受欢迎，可用于对不同类型的项目进行聚类。为了测试我们的算法，您将实现一个应用程序来对一组文档进行聚类。作为文档集合，我们使用了我们在第四章中介绍的有关电影语料库的维基百科页面的缩减版本，*从任务获取数据 - Callable 和 Future 接口*。我们只取了 1,000 个文档。为了表示每个文档，我们必须使用向量空间模型表示。通过这种表示，每个文档都表示为一个数值向量，其中向量的每个维度表示一个单词或术语，其值是定义该单词或术语在文档中重要性的度量。

当您使用向量空间模型表示文档集合时，向量的维度将与整个集合中不同单词的数量一样多，因此向量将具有许多零值，因为每个文档并不包含所有单词。您可以使用更优化的内存表示来避免所有这些零值，并节省内存，从而提高应用程序的性能。

在我们的情况下，我们选择**词项频率-逆文档频率**（**tf-idf**）作为定义每个词的重要性的度量标准，并选择具有更高 tf-idf 的 50 个词作为代表每个文档的词语。

我们使用两个文件：`movies.words`文件存储了向量中使用的所有单词的列表，而`movies.data`存储了每个文档的表示。`movies.data`文件的格式如下：

```java
10000202,rabona:23.039285705435507,1979:8.09314752937111,argentina:7.953798614698405,la:5.440565539075689,argentine:4.058577338363469,editor:3.0401515284855267,spanish:2.9692083275217134,image_size:1.3701158713905104,narrator:1.1799670194306195,budget:0.286193223652206,starring:0.25519156764102785,cast:0.2540127604060545,writer:0.23904044207902764,distributor:0.20430284744786784,cinematography:0.182583823735518,music:0.1675671228903468,caption:0.14545085918028047,runtime:0.127767002869991,country:0.12493801913495534,producer:0.12321749670640451,director:0.11592975672109682,links:0.07925582303812376,image:0.07786973207561361,external:0.07764427108746134,released:0.07447174080087617,name:0.07214163435745059,infobox:0.06151153983466272,film:0.035415118094854446
```

在这里，`10000202`是文档的标识符，文件的其余部分遵循`word:tfxidf`的格式。

与其他示例一样，我们将实现串行和并发版本，并执行两个版本以验证 Fork/Join 框架是否提高了该算法的性能。

## 常见的类

串行和并发版本之间有一些共享的部分。这些部分包括：

+   `VocabularyLoader`：这是一个加载构成我们语料库词汇表的单词列表的类。

+   `Word`，`Document`和`DocumentLoader`：这三个类用于加载有关文档的信息。这些类在串行和并发版本的算法之间有一些差异。

+   `DistanceMeasure`：这是一个计算两个向量之间的**欧几里得**距离的类。

+   `DocumentCluster`：这是一个存储有关聚类信息的类。

让我们详细看看这些类。

### VocabularyLoader 类

正如我们之前提到的，我们的数据存储在两个文件中。其中一个文件是`movies.words`文件。该文件存储了文档中使用的所有单词的列表。`VocabularyLoader`类将该文件转换为`HashMap`。`HashMap`的键是整个单词，值是该单词在列表中的索引的整数值。我们使用该索引来确定表示每个文档的向量空间模型中单词的位置。

该类只有一个名为`load()`的方法，该方法接收文件路径作为参数并返回`HashMap`：

```java
public class VocabularyLoader {

    public static Map<String, Integer> load (Path path) throws IOException {
        int index=0;
        HashMap<String, Integer> vocIndex=new HashMap<String, Integer>();
        try(BufferedReader reader = Files.newBufferedReader(path)){
            String line = null;
            while ((line = reader.readLine()) != null) {
                vocIndex.put(line,index );
                index++;
            }
        }
        return vocIndex;

    }
}
```

### Word，Document 和 DocumentLoader 类

这些类存储了我们算法中将使用的所有文档信息。首先，`Word`类存储了文档中单词的信息。它包括单词的索引和文档中该单词的 tf-idf。该类仅包括这些属性（分别为`int`和`double`），并实现了`Comparable`接口，以使用它们的 tf-idf 值对两个单词进行排序，因此我们不包括此类的源代码。

`Document`类存储有关文档的所有相关信息。首先是一个包含文档中单词的`Word`对象数组。这是我们的向量空间模型的表示。我们只存储文档中使用的单词，以节省大量内存空间。然后是一个包含存储文档的文件名的`String`，最后是一个`DocumentCluster`对象，用于知道与文档关联的聚类。它还包括一个用于初始化这些属性的构造函数和用于获取和设置它们的值的方法。我们只包括`setCluster()`方法的代码。在这种情况下，此方法将返回一个布尔值，以指示此属性的新值是否与旧值相同或新值。我们将使用该值来确定是否停止算法：

```java
public boolean setCluster(DocumentCluster cluster) {
    if (this.cluster == cluster) {
        return false;
    } else {
        this.cluster = cluster;
        return true;
    }
}
```

最后，`DocumentLoader`类加载有关文档的信息。它包括一个静态方法`load()`，该方法接收文件的路径和包含词汇表的`HashMap`，并返回`Document`对象的`Array`。它逐行加载文件并将每行转换为`Document`对象。我们有以下代码：

```java
public static Document[] load(Path path, Map<String, Integer> vocIndex) throws IOException{
    List<Document> list = new ArrayList<Document>();
    try(BufferedReader reader = Files.newBufferedReader(path)) {
        String line = null;
        while ((line = reader.readLine()) != null) {
            Document item = processItem(line, vocIndex);
            list.add(item);
        }
    }
    Document[] ret = new Document[list.size()];
    return list.toArray(ret);

}
```

要将文本文件的一行转换为`Document`对象，我们使用`processItem()`方法：

```java
private static Document processItem(String line,Map<String, Integer> vocIndex) {

    String[] tokens = line.split(",");
    int size = tokens.length - 1;

    Document document = new Document(tokens[0], size);
    Word[] data = document.getData();

    for (int i = 1; i < tokens.length; i++) {
        String[] wordInfo = tokens[i].split(":");
        Word word = new Word();
        word.setIndex(vocIndex.get(wordInfo[0]));
        word.setTfidf(Double.parseDouble(wordInfo[1]));
        data[i - 1] = word;
    }
    Arrays.sort(data);
    return document;
}
```

正如我们之前提到的，行中的第一项是文档的标识符。我们从`tokens[0]`获取它，并将其传递给`Document`类的构造函数。然后，对于其余的标记，我们再次拆分它们以获取每个单词的信息，包括整个单词和 tf-idf 值。

### `DistanceMeasurer`类

该类计算文档与聚类（表示为向量）之间的欧氏距离。在对我们的单词数组进行排序后，单词按照与质心数组相同的顺序排列，但有些单词可能不存在。对于这样的单词，我们假设 tf-idf 为零，因此距离就是来自质心数组的相应值的平方：

```java
public class DistanceMeasurer {

    public static double euclideanDistance(Word[] words, double[] centroid) {
        double distance = 0;

        int wordIndex = 0;
        for (int i = 0; i < centroid.length; i++) {
            if ((wordIndex < words.length) (words[wordIndex].getIndex() == i)) {
                distance += Math.pow( (words[wordIndex].getTfidf() - centroid[i]), 2);
                wordIndex++;
            } else {
                distance += centroid[i] * centroid[i];
            }
        }

        return Math.sqrt(distance);
    }
}
```

### 文档聚类类

该类存储算法生成的每个聚类的信息。此信息包括与该聚类关联的所有文档的列表以及表示该聚类的向量的质心。在这种情况下，该向量的维度与词汇表中的单词数量相同。该类具有两个属性，一个用于初始化它们的构造函数，以及用于获取和设置它们的值的方法。它还包括两个非常重要的方法。首先是`calculateCentroid()`方法。它计算聚类的质心，作为表示与该聚类关联的文档的向量的平均值。我们有以下代码：

```java
public void calculateCentroid() {

    Arrays.fill(centroid, 0);

    for (Document document : documents) {
        Word vector[] = document.getData();

        for (Word word : vector) {
            centroid[word.getIndex()] += word.getTfidf();
        }
    }

    for (int i = 0; i < centroid.length; i++) {
        centroid[i] /= documents.size();
    }
}
```

第二种方法是`initialize()`方法，它接收一个`Random`对象，并使用随机数初始化聚类的质心向量如下：

```java
public void initialize(Random random) {
    for (int i = 0; i < centroid.length; i++) {
        centroid[i] = random.nextDouble();
    }
}
```

## 串行版本

一旦我们描述了应用程序的共同部分，让我们看看如何实现 k-means 聚类算法的串行版本。我们将使用两个类：`SerialKMeans`，它实现了该算法，以及`SerialMain`，它实现了执行该算法的`main()`方法。

### `SerialKMeans`类

`SerialKMeans`类实现了 k-means 聚类算法的串行版本。该类的主要方法是`calculate()`方法。它接收以下参数：

+   包含有关文档的`Document`对象的数组

+   您想要生成的聚类数

+   词汇表的大小

+   随机数生成器的种子

该方法返回`DocumentCluster`对象的`Array`。每个聚类将有与之关联的文档列表。首先，文档通过`numberClusters`参数确定`Array`的聚类，并使用`initialize()`方法和`Random`对象对它们进行初始化，如下所示：

```java
public class SerialKMeans {

    public static DocumentCluster[] calculate(Document[] documents, int clusterCount, int vocSize, int seed) {
        DocumentCluster[] clusters = new DocumentCluster[clusterCount];

        Random random = new Random(seed);
        for (int i = 0; i < clusterCount; i++) {
            clusters[i] = new DocumentCluster(vocSize);
            clusters[i].initialize(random);
        }
```

然后，我们重复分配和更新阶段，直到所有文档都留在同一个集群中。最后，我们返回具有文档最终组织的集群数组如下：

```java
        boolean change = true;

        int numSteps = 0;
        while (change) {
            change = assignment(clusters, documents);
            update(clusters);
            numSteps++;
        }
        System.out.println("Number of steps: "+numSteps);
        return clusters;
    }
```

分配阶段在`assignment()`方法中实现。该方法接收`Document`和`DocumentCluster`对象数组。对于每个文档，它计算文档与所有集群之间的欧几里德距离，并将文档分配给距离最近的集群。它返回一个布尔值，指示一个或多个文档是否从一步到下一步更改了其分配的集群。我们有以下代码：

```java
private static boolean assignment(DocumentCluster[] clusters, Document[] documents) {

    boolean change = false;

    for (DocumentCluster cluster : clusters) {
        cluster.clearClusters();
    }

    int numChanges = 0;
    for (Document document : documents) {
        double distance = Double.MAX_VALUE;
        DocumentCluster selectedCluster = null;
        for (DocumentCluster cluster : clusters) {
            double curDistance = DistanceMeasurer.euclideanDistance(document.getData(), cluster.getCentroid());
            if (curDistance < distance) {
                distance = curDistance;
                selectedCluster = cluster;
            }
        }
        selectedCluster.addDocument(document);
        boolean result = document.setCluster(selectedCluster);
        if (result)
            numChanges++;
    }
    System.out.println("Number of Changes: " + numChanges);
    return numChanges > 0;
}
```

更新步骤在`update()`方法中实现。它接收具有集群信息的`DocumentCluster`数组，并简单地重新计算每个集群的质心。

```java
    private static void update(DocumentCluster[] clusters) {
        for (DocumentCluster cluster : clusters) {
            cluster.calculateCentroid();
        }

    }

}
```

`SerialMain`类包括`main()`方法来启动 k-means 算法的测试。首先，它从文件中加载数据（单词和文档）：

```java
public class SerialMain {

    public static void main(String[] args) {
        Path pathVoc = Paths.get("data", "movies.words");

        Map<String, Integer> vocIndex=VocabularyLoader.load(pathVoc);
        System.out.println("Voc Size: "+vocIndex.size());

        Path pathDocs = Paths.get("data", "movies.data");
        Document[] documents = DocumentLoader.load(pathDocs, vocIndex);
        System.out.println("Document Size: "+documents.length);
```

然后，它初始化我们要生成的集群数量和随机数生成器的种子。如果它们不作为`main()`方法的参数传入，我们将使用默认值如下：

```java
    if (args.length != 2) {
        System.err.println("Please specify K and SEED");
        return;
    }
    int K = Integer.valueOf(args[0]);
    int SEED = Integer.valueOf(args[1]);
}
```

最后，我们启动算法，测量其执行时间，并写入每个集群的文档数量。

```java
        Date start, end;
        start=new Date();
        DocumentCluster[] clusters = SerialKMeans.calculate(documents, K ,vocIndex.size(), SEED);
        end=new Date();
        System.out.println("K: "+K+"; SEED: "+SEED);
        System.out.println("Execution Time: "+(end.getTime()- start.getTime()));
        System.out.println(
            Arrays.stream(clusters).map (DocumentCluster::getDocumentCount).sorted (Comparator.reverseOrder())
                        .map(Object::toString).collect( Collectors.joining(", ", "Cluster sizes: ", "")));
    }
}
```

## 并发版本

为了实现算法的并发版本，我们使用了 Fork/Join 框架。我们基于`RecursiveAction`类实现了两个不同的任务。正如我们之前提到的，当您希望使用 Fork/Join 框架处理不返回结果的任务时，我们实现了分配和更新阶段作为要在 Fork/Join 框架中执行的任务。

为了实现 k-means 算法的并发版本，我们将修改一些常见类以使用并发数据结构。然后，我们将实现两个任务，最后，我们将实现实现算法的并发版本的`ConcurrentKMeans`和用于测试的`ConcurrentMain`类。

### Fork/Join 框架的两个任务 - AssignmentTask 和 UpdateTask

正如我们之前提到的，我们已经将分配和更新阶段实现为 Fork/Join 框架中要实现的任务。

分配阶段将文档分配给与文档具有最小欧几里德距离的集群。因此，我们必须处理所有文档并计算所有文档和所有集群的欧几里德距离。我们将使用任务需要处理的文档数量作为控制是否需要拆分任务的度量标准。我们从需要处理所有文档的任务开始，直到我们将它们拆分为需要处理小于预定义大小的文档数量的任务。

`AssignmentTask`类具有以下属性：

+   具有集群数据的`ConcurrentDocumentCluster`对象数组

+   具有文档数据的`ConcurrentDocument`对象数组

+   有两个整数属性`start`和`end`，确定任务需要处理的文档数量

+   一个`AtomicInteger`属性`numChanges`，存储从上次执行到当前执行更改其分配的集群的文档数量

+   一个整数属性`maxSize`，存储任务可以处理的最大文档数量

我们已经实现了一个构造函数来初始化所有这些属性和方法来获取和设置它的值。

这些任务的主要方法（与每个任务一样）是`compute()`方法。首先，我们检查任务需要处理的文档数量。如果小于或等于`maxSize`属性，则处理这些文档。我们计算每个文档与所有聚类之间的欧氏距离，并选择距离最小的聚类。如果有必要，我们使用`incrementAndGet()`方法增加`numChanges`原子变量。原子变量可以在不使用同步机制的情况下由多个线程同时更新，而不会导致任何内存不一致。参考以下代码：

```java
protected void compute() {
    if (end - start <= maxSize) {
        for (int i = start; i < end; i++) {
            ConcurrentDocument document = documents[i];
            double distance = Double.MAX_VALUE;
            ConcurrentDocumentCluster selectedCluster = null;
            for (ConcurrentDocumentCluster cluster : clusters) {
                double curDistance = DistanceMeasurer.euclideanDistance (document.getData(), cluster.getCentroid());
                if (curDistance < distance) {
                    distance = curDistance;
                    selectedCluster = cluster;
                }
            }
            selectedCluster.addDocument(document);
            boolean result = document.setCluster(selectedCluster);
            if (result) {
                numChanges.incrementAndGet();
            }

        }
```

如果任务需要处理的文档数量太大，我们将该集合分成两部分，并创建两个新任务来处理每一部分，如下所示：

```java
    } else {
        int mid = (start + end) / 2;
        AssignmentTask task1 = new AssignmentTask(clusters, documents, start, mid, numChanges, maxSize);
        AssignmentTask task2 = new AssignmentTask(clusters, documents, mid, end, numChanges, maxSize);

        invokeAll(task1, task2);
    }
}
```

为了在 Fork/Join 池中执行这些任务，我们使用了`invokeAll()`方法。该方法将在任务完成执行时返回。

更新阶段重新计算每个聚类的质心作为所有文档的平均值。因此，我们必须处理所有聚类。我们将使用任务需要处理的聚类数量作为控制任务是否需要分割的度量。我们从需要处理所有聚类的任务开始，并将其分割，直到我们有需要处理的聚类数量低于预定义大小的任务。

`UpdateTask`类具有以下属性：

+   包含聚类数据的`ConcurrentDocumentCluster`对象数组

+   确定任务需要处理的聚类数量的整数属性`start`和`end`

+   一个整数属性`maxSize`，用于存储任务可以处理的最大聚类数

我们已经实现了一个构造函数来初始化所有这些属性和方法来获取和设置其值。

`compute()`方法首先检查任务需要处理的聚类数量。如果该数量小于或等于`maxSize`属性，则处理这些聚类并更新它们的质心。

```java
@Override
protected void compute() {
    if (end - start <= maxSize) {
        for (int i = start; i < end; i++) {
            ConcurrentDocumentCluster cluster = clusters[i];
            cluster.calculateCentroid();
        }
```

如果任务需要处理的聚类数量太大，我们将把任务需要处理的聚类集合分成两部分，并创建两个任务来处理每一部分，如下所示：

```java
    } else {
        int mid = (start + end) / 2;
        UpdateTask task1 = new UpdateTask(clusters, start, mid, maxSize);
        UpdateTask task2 = new UpdateTask(clusters, mid, end, maxSize);

        invokeAll(task1, task2);
    }
}
```

### 并发 K 均值类

`ConcurrentKMeans`类实现了并发版本的 k 均值聚类算法。与串行版本一样，该类的主要方法是`calculate()`方法。它接收以下参数：

+   包含有关文档信息的`ConcurrentDocument`对象数组

+   您想要生成的聚类数量

+   词汇量的大小

+   随机数生成器的种子

+   Fork/Join 任务在不分割任务的情况下处理的最大项目数

`calculate()`方法返回一个包含聚类信息的`ConcurrentDocumentCluster`对象数组。每个聚类都有与之关联的文档列表。首先，文档根据`numberClusters`参数创建聚类数组，并使用`initialize()`方法和`Random`对象进行初始化：

```java
public class ConcurrentKMeans {

    public static ConcurrentDocumentCluster[] calculate(ConcurrentDocument[] documents int numberCluster int vocSize, int seed, int maxSize) {
        ConcurrentDocumentCluster[] clusters = new ConcurrentDocumentCluster[numberClusters];

        Random random = new Random(seed);
        for (int i = 0; i < numberClusters; i++) {
            clusters[i] = new ConcurrentDocumentCluster(vocSize);
            clusters[i].initialize(random);
        }
```

然后，我们重复分配和更新阶段，直到所有文档都留在同一个聚类中。在循环之前，我们创建一个将执行该任务及其所有子任务的`ForkJoinPool`。一旦循环结束，与其他`Executor`对象一样，我们必须使用`shutdown()`方法来结束 Fork/Join 池的执行。最后，我们返回具有文档最终组织的聚类数组：

```java
        boolean change = true;
        ForkJoinPool pool = new ForkJoinPool();

        int numSteps = 0;
        while (change) {
            change = assignment(clusters, documents, maxSize, pool);
            update(clusters, maxSize, pool);
            numSteps++;
        }
        pool.shutdown();
        System.out.println("Number of steps: "+numSteps); return clusters;
    }
```

分配阶段在`assignment()`方法中实现。该方法接收聚类数组、文档数组和`maxSize`属性。首先，我们删除所有聚类的关联文档列表：

```java
    private static boolean assignment(ConcurrentDocumentCluster[] clusters, ConcurrentDocument[] documents, int maxSize, ForkJoinPool pool) {

        boolean change = false;

        for (ConcurrentDocumentCluster cluster : clusters) {
            cluster.clearDocuments();
        }
```

然后，我们初始化必要的对象：一个`AtomicInteger`来存储已更改其分配簇的文档数量，以及将开始该过程的`AssignmentTask`。

```java
        AtomicInteger numChanges = new AtomicInteger(0);
        AssignmentTask task = new AssignmentTask(clusters, documents, 0, documents.length, numChanges, maxSize);

```

然后，我们使用`ForkJoinPool`的`execute()`方法以异步方式执行池中的任务，并使用`AssignmentTask`对象的`join()`方法等待其完成，如下所示：

```java
        pool.execute(task);
        task.join();
```

最后，我们检查已更改其分配的簇的文档数量。如果有更改，我们返回`true`值。否则，我们返回`false`值。我们有以下代码：

```java
        System.out.println("Number of Changes: " + numChanges);
        return numChanges.get() > 0;
    }
```

更新阶段在`update()`方法中实现。它接收簇数组和`maxSize`参数。首先，我们创建一个`UpdateTask`对象来更新所有簇。然后，我们在`ForkJoinPool`对象中执行该任务，方法接收如下参数：

```java
    private static void update(ConcurrentDocumentCluster[] clusters, int maxSize, ForkJoinPool pool) {
        UpdateTask task = new UpdateTask(clusters, 0, clusters.length, maxSize, ForkJoinPool pool);
         pool.execute(task);
         task.join();
    }
}
```

### `ConcurrentMain`类

`ConcurrentMain`类包括`main()`方法，用于启动 k-means 算法的测试。其代码与`SerialMain`类相同，但将串行类更改为并发类。

## 比较解决方案

为了比较这两种解决方案，我们执行了不同的实验，改变了三个不同参数的值。

+   k 参数将确定我们要生成的簇的数量。我们已使用值 5、10、15 和 20 测试了算法。

+   `Random`数生成器的种子。此种子确定初始质心位置。我们已使用值 1 和 13 测试了算法。

+   对于并发算法，`maxSize`参数确定任务在不被拆分为其他任务的情况下可以处理的最大项目（文档或簇）数量。我们已使用值 1、20 和 400 测试了算法。

我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行了实验，该框架允许在 Java 中实现微基准测试。使用基准测试框架比简单使用`currentTimeMillis()`或`nanoTime()`等方法测量时间更好。我们在具有四核处理器的计算机上执行了 10 次，并计算了这 10 次的平均执行时间。以下是我们以毫秒为单位获得的执行时间：

|   |   | 串行 | 并发 |
| --- | --- | --- | --- |
| **K** | **Seed** |   | **MaxSize=1** | **MaxSize=20** | **maxSize=400** |
| 5 | 1 | 6676.141 | 4696.414 | 3291.397 | 3179.673 |
| 10 | 1 | 6780.088 | 3365.731 | 2970.056 | 2825.488 |
| 15 | 1 | 12936.178 | 5308.734 | 4737.329 | 4490.443 |
| 20 | 1 | 19824.729 | 7937.820 | 7347.445 | 6848.873 |
| 5 | 13 | 3738.869 | 2714.325 | 1984.152 | 1916.053 |
| 10 | 13 | 9567.416 | 4693.164 | 3892.526 | 3739.129 |
| 15 | 13 | 12427.589 | 5598.996 | 4735.518 | 4468.721 |
| 20 | 13 | 18157.913 | 7285.565 | 6671.283 | 6325.664 |

我们可以得出以下结论：

+   种子对执行时间有重要且不可预测的影响。有时，种子 13 的执行时间较低，但其他时候种子 1 的执行时间较低。

+   当增加簇的数量时，执行时间也会增加。

+   `maxSize`参数对执行时间影响不大。参数 K 或 seed 对执行时间影响更大。如果增加参数值，将获得更好的性能。1 和 20 之间的差异比 20 和 400 之间的差异更大。

+   在所有情况下，并发版本的算法性能均优于串行版本。

例如，如果我们将参数 K=20 和 seed=13 的串行算法与参数 K=20、seed=13 和 maxSize=400 的并发版本进行比较，使用加速比，我们将获得以下结果：

![比较解决方案](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00017.jpeg)

# 第二个例子 - 数据过滤算法

假设您有大量描述物品列表的数据。例如，您有很多人的属性（姓名、姓氏、地址、电话号码等）。通常需要获取满足某些条件的数据，例如，您想获取住在特定街道或具有特定姓名的人的数据。

在这一部分，您将实现其中一个过滤程序。我们使用了 UCI 的**Census-Income KDD**数据集（您可以从[`archive.ics.uci.edu/ml/datasets/Census-Income+%28KDD%29`](https://archive.ics.uci.edu/ml/datasets/Census-Income+%28KDD%29)下载），其中包含了从美国人口普查局 1994 年和 1995 年进行的加权人口普查数据。

在这个示例的并发版本中，您将学习如何取消在 Fork/Join 池中运行的任务，以及如何处理任务中可能抛出的未经检查的异常。

## 共同部分

我们已经实现了一些类来从文件中读取数据和过滤数据。这些类被算法的串行和并发版本使用。这些类包括：

+   `CensusData`类：这个类存储了定义每个人的 39 个属性。它定义了获取和设置它们值的属性和方法。我们将通过数字来标识每个属性。这个类的`evaluateFilter()`方法包含了数字和属性名称之间的关联。您可以查看文件[`archive.ics.uci.edu/ml/machine-learning-databases/census-income-mld/census-income.names`](https://archive.ics.uci.edu/ml/machine-learning-databases/census-income-mld/census-income.names)来获取每个属性的详细信息。

+   `CensusDataLoader`类：这个类从文件中加载人口普查数据。它有一个`load()`方法，接收文件路径作为输入参数，并返回一个包含文件中所有人的信息的`CensusData`数组。

+   `FilterData`类：这个类定义了数据的过滤器。过滤器包括属性的编号和属性的值。

+   `Filter`类：这个类实现了确定`CensusData`对象是否满足一系列过滤条件的方法。

我们不包括这些类的源代码。它们非常简单，您可以查看示例的源代码。

## 串行版本

我们已经在两个类中实现了过滤算法的串行版本。`SerialSearch`类进行数据过滤。它提供了两种方法：

+   `findAny()`方法：它接收`CensusData`对象数组作为参数，其中包含来自文件的所有数据，以及一系列过滤器，并返回一个`CensusData`对象，其中包含满足所有过滤器条件的第一个人的数据。

+   `findAll()`方法：它接收`CensusData`对象数组作为参数，其中包含来自文件的所有数据，以及一系列过滤器，并返回一个`CensusData`对象数组，其中包含满足所有过滤器条件的所有人的数据。

`SerialMain`类实现了这个版本的`main()`方法，并对其进行了测试，以测量在某些情况下该算法的执行时间。

### SerialSearch 类

如前所述，这个类实现了数据的过滤。它提供了两种方法。第一个方法`findAny()`查找满足过滤器条件的第一个数据对象。当它找到第一个数据对象时，它就结束了执行。参考以下代码：

```java
public class SerialSearch {

    public static CensusData findAny (CensusData[] data, List<FilterData> filters) {
        int index=0;
        for (CensusData censusData : data) {
            if (Filter.filter(censusData, filters)) {
                System.out.println("Found: "+index);
                return censusData;
            }
            index++;
        }

        return null;
    }
```

第二个方法`findAll()`返回一个`CensusData`对象数组，其中包含满足过滤器条件的所有对象，如下所示：

```java
    public static List<CensusData> findAll (CensusData[] data, List<FilterData> filters) {
        List<CensusData> results=new ArrayList<CensusData>();

        for (CensusData censusData : data) {
            if (Filter.filter(censusData, filters)) {
                results.add(censusData);
            }
        }
        return results;
    }
}
```

### SerialMain 类

您将使用这个类来测试不同情况下的过滤算法。首先，我们从文件中加载数据，如下所示：

```java
public class SerialMain {
    public static void main(String[] args) {
        Path path = Paths.get("data","census-income.data");

        CensusData data[]=CensusDataLoader.load(path);
        System.out.println("Number of items: "+data.length);

        Date start, end;
```

我们要测试的第一种情况是使用`findAny()`方法来查找数组的前几个位置中存在的对象。您构建一个过滤器列表，然后使用文件的数据和过滤器列表调用`findAny()`方法：

```java
        List<FilterData> filters=new ArrayList<>();
        FilterData filter=new FilterData();
        filter.setIdField(32);
        filter.setValue("Dominican-Republic");
        filters.add(filter);
        filter=new FilterData();
        filter.setIdField(31);
        filter.setValue("Dominican-Republic");
        filters.add(filter);
        filter=new FilterData();
        filter.setIdField(1);
        filter.setValue("Not in universe");
        filters.add(filter);
        filter=new FilterData();
        filter.setIdField(14);
        filter.setValue("Not in universe");
        filters.add(filter);
        start=new Date();
        CensusData result=SerialSearch.findAny(data, filters);
        System.out.println("Test 1 - Result: "+result.getReasonForUnemployment());
        end=new Date();
        System.out.println("Test 1- Execution Time: "+(end.getTime()-start.getTime()));
```

我们的过滤器寻找以下属性：

+   `32`：这是出生父亲的国家属性

+   `31`：这是出生母亲的国家属性

+   `1`：这是工人属性的类；`Not in universe`是它们可能的值之一

+   `14`：这是失业原因属性；`Not in universe`是它们可能的值之一

我们将按以下方式测试其他情况：

+   使用`findAny()`方法查找数组中最后几个位置中存在的对象

+   使用`findAny()`方法尝试查找一个不存在的对象

+   在错误情况下使用`findAny()`方法

+   使用`findAll()`方法获取满足一系列过滤器的所有对象

+   在错误情况下使用`findAll()`方法

## 并发版本

我们将在我们的并发版本中包含更多元素：

+   任务管理器：当您使用 Fork/Join 框架时，您从一个任务开始，然后将该任务分成两个（或更多）子任务，然后再次分割，直到您的问题达到所需的大小。有时您希望完成所有这些任务的执行。例如，当您实现`findAny()`方法并找到满足所有条件的对象时，您就不需要继续执行其余任务。

+   一个`RecursiveTask`类来实现`findAny()`方法：它是扩展了`RecursiveTask`的`IndividualTask`类。

+   一个`RecursiveTask`类来实现`findAll()`方法：它是扩展了`RecursiveTask`的`ListTask`类。

让我们看看所有这些类的细节。

### 任务管理器类

我们将使用这个类来控制任务的取消。我们将在以下两种情况下取消任务的执行：

+   您正在执行`findAny()`操作，并且找到一个满足要求的对象

+   您正在执行`findAny()`或`findAll()`操作，并且其中一个任务出现了未经检查的异常

该类声明了两个属性：`ConcurrentLinkedDeque`用于存储我们需要取消的所有任务，以及`AtomicBoolean`变量来保证只有一个任务执行`cancelTasks()`方法：

```java
public class TaskManager {

    private Set<RecursiveTask> tasks;
    private AtomicBoolean cancelled;

    public TaskManager() {
        tasks = ConcurrentHashMap.newKeySet();
        cancelled = new AtomicBoolean(false);
    }
```

它定义了添加任务到`ConcurrentLinkedDeque`，从`ConcurrentLinkedDeque`中删除任务以及取消其中存储的所有任务的方法。要取消任务，我们使用`ForkJoinTask`类中定义的`cancel()`方法。如果任务正在运行，则`true`参数会强制中断任务的执行，如下所示：

```java
    public void addTask(RecursiveTask task) {
        tasks.add(task);
    }

    public void cancelTasks(RecursiveTask sourceTask) {

        if (cancelled.compareAndSet(false, true)) {
            for (RecursiveTask task : tasks) {
                if (task != sourceTask) {
                    if(cancelled.get()) {
                        task.cancel(true);
                    } 
                    else {
                        tasks.add(task);
                    }
                }
            }
        }
    }

    public void deleteTask(RecursiveTask task) {
        tasks.remove(task);
    }
```

`cancelTasks()`方法接收一个`RecursiveTask`对象作为参数。我们将取消除调用此方法的任务之外的所有任务。我们不想取消已经找到结果的任务。`compareAndSet(false, true)`方法将`AtomicBoolean`变量设置为`true`，并且仅当当前值为`false`时返回`true`。如果`AtomicBoolean`变量已经有一个`true`值，则返回`false`。整个操作是原子性执行的，因此可以保证即使从不同的线程并发调用`cancelTasks()`方法多次，if 语句的主体也最多只会执行一次。

### 个人任务类

`IndividualTask`类扩展了参数化为`CensusData`任务的`RecursiveTask`类，并实现了`findAny()`操作。它定义了以下属性：

+   一个包含所有`CensusData`对象的数组

+   确定它需要处理的元素的`start`和`end`属性

+   `size`属性确定任务在不分割的情况下将处理的最大元素数量

+   一个`TaskManager`类来取消任务（如果有必要）

+   以下代码提供了要应用的过滤器列表：

```java
private CensusData[] data;
private int start, end, size;
private TaskManager manager;
private List<FilterData> filters;

public IndividualTask(CensusData[] data, int start, int end, TaskManager manager, int size, List<FilterData> filters) {
    this.data = data;
    this.start = start;
    this.end = end;
    this.manager = manager;
    this.size = size;
    this.filters = filters;
}
```

该类的主要方法是`compute()`方法。它返回一个`CensusData`对象。如果任务需要处理的元素数量少于 size 属性，则直接查找对象。如果方法找到所需的对象，则返回该对象并使用`cancelTasks()`方法取消其余任务的执行。如果方法找不到所需的对象，则返回 null。我们有以下代码：

```java
if (end - start <= size) {
    for (int i = start; i < end && ! Thread.currentThread().isInterrupted(); i++) {
        CensusData censusData = data[i];
        if (Filter.filter(censusData, filters)) {
            System.out.println("Found: " + i);
            manager.cancelTasks(this);
            return censusData;
            }
        }
        return null;
    }
```

如果它需要处理的项目数量超过 size 属性，则创建两个子任务来处理一半的元素：

```java
        } else {
            int mid = (start + end) / 2;
            IndividualTask task1 = new IndividualTask(data, start, mid, manager, size, filters);
            IndividualTask task2 = new IndividualTask(data, mid, end, manager, size, filters);
```

然后，我们将新创建的任务添加到任务管理器中，并删除实际的任务。如果我们想要取消任务，我们只想取消正在运行的任务：

```java
            manager.addTask(task1);
            manager.addTask(task2);
            manager.deleteTask(this);
```

然后，我们使用`fork()`方法将任务发送到`ForkJoinPool`，以异步方式发送它们，并使用`quietlyJoin()`方法等待其完成。`join()`和`quietlyJoin()`方法之间的区别在于，`join()`方法在任务被取消或方法内部抛出未检查的异常时会抛出异常，而`quietlyJoin()`方法不会抛出任何异常。

```java
            task1.fork();
            task2.fork();
            task1.quietlyJoin();
            task2.quietlyJoin();
```

然后，我们按以下方式从`TaskManager`类中删除子任务：

```java
            manager.deleteTask(task1);
            manager.deleteTask(task2);
```

现在，我们使用`join()`方法获取任务的结果。如果任务抛出未检查的异常，它将被传播而不进行特殊处理，并且取消将被忽略，如下所示：

```java
        try {
            CensusData res = task1.join();
            if (res != null)
                return res;
                manager.deleteTask(task1);
        } catch (CancellationException ex) {
        }
        try {
            CensusData res = task2.join();
            if (res != null)
                return res;
            manager.deleteTask(task2);
        } catch (CancellationException ex) {
        }
        return null;
    }
}
```

### ListTask 类

`ListTask`类扩展了参数为`List`的`CensusData`的`RecursiveTask`类。我们将使用这个任务来实现`findAll()`操作。它与`IndividualTask`任务非常相似。两者都使用相同的属性，但在`compute()`方法中有所不同。

首先，我们初始化一个`List`对象来返回结果并检查任务需要处理的元素数量。如果任务需要处理的元素数量少于 size 属性，则将满足过滤器指定条件的所有对象添加到结果列表中：

```java
@Override
protected List<CensusData> compute() {
    List<CensusData> ret = new ArrayList<CensusData>();
    if (end - start <= size) {
        for (int i = start; i < end; i++) {
            CensusData censusData = data[i];
            if (Filter.filter(censusData, filters)) {
                ret.add(censusData);
            }
        }
```

如果它需要处理的项目数量超过 size 属性，则创建两个子任务来处理一半的元素：

```java
        int mid = (start + end) / 2;
        ListTask task1 = new ListTask(data, start, mid, manager, size, filters);
        ListTask task2 = new ListTask(data, mid, end, manager, size, filters);
```

然后，我们将新创建的任务添加到任务管理器中，并删除实际的任务。实际任务不会被取消；其子任务将被取消，如下所示：

```java
        manager.addTask(task1);
        manager.addTask(task2);
        manager.deleteTask(this);
```

然后，我们使用`fork()`方法将任务发送到`ForkJoinPool`，以异步方式发送它们，并使用`quietlyJoin()`方法等待其完成：

```java
        task1.fork();
        task2.fork();
        task2.quietlyJoin();
        task1.quietlyJoin();
```

然后，我们将从`TaskManager`中删除子任务：

```java
        manager.deleteTask(task1);
        manager.deleteTask(task2);
```

现在，我们使用`join()`方法获取任务的结果。如果任务抛出未检查的异常，它将被传播而不进行特殊处理，并且取消将被忽略：

```java
   try {
    List<CensusData> tmp = task1.join();
    if (tmp != null)
     ret.addAll(tmp);
    manager.deleteTask(task1);
   } catch (CancellationException ex) {
   }
   try {
    List<CensusData> tmp = task2.join();
    if (tmp != null)
     ret.addAll(tmp);
    manager.deleteTask(task2);
   } catch (CancellationException ex) {
   }
```

### ConcurrentSearch 类

ConcurrentSearch 类实现了`findAny()`和`findAll()`方法。它们与串行版本的方法具有相同的接口。在内部，它们初始化了`TaskManager`对象和第一个任务，并使用`execute`方法发送到默认的`ForkJoinPool`；它们等待任务的完成并写入结果。这是`findAny()`方法的代码：

```java
public class ConcurrentSearch {

    public static CensusData findAny (CensusData[] data, List<FilterData> filters, int size) {
        TaskManager manager=new TaskManager();
        IndividualTask task=new IndividualTask(data, 0, data.length, manager, size, filters);
        ForkJoinPool.commonPool().execute(task);
        try {
            CensusData result=task.join();
            if (result!=null) {
                System.out.println("Find Any Result: "+result.getCitizenship());
            return result;
        } catch (Exception e) {
            System.err.println("findAny has finished with an error: "+task.getException().getMessage());
        }

        return null;
    }
```

这是`findAll()`方法的代码：

```java
    public static CensusData[] findAll (CensusData[] data, List<FilterData> filters, int size) {
        List<CensusData> results;
        TaskManager manager=new TaskManager();
        ListTask task=new ListTask(data,0,data.length,manager, size,filters);
        ForkJoinPool.commonPool().execute(task);
        try {
            results=task.join();

            return results;
        } catch (Exception e) {
            System.err.println("findAny has finished with an error: " + task.getException().getMessage());
        }
        return null;
    }
```

### ConcurrentMain 类

`ConcurrentMain`类用于测试对象过滤的并行版本。它与`SerialMain`类相同，但使用操作的并行版本。

## 比较两个版本

比较过滤算法的串行和并行版本，我们在六种不同的情况下对它们进行了测试：

+   **测试 1**：我们测试`findAny()`方法，查找存在于`CensusData`数组的第一个位置的对象

+   **测试 2**：我们测试`findAny()`方法，查找存在于`CensusData`数组的最后位置的对象

+   **测试 3**：我们测试`findAny()`方法，查找不存在的对象

+   **测试 4**：我们测试`findAny()`方法在错误情况下

+   **测试 5**：我们测试`findAll()`方法在正常情况下

+   **测试 6**：我们测试`findAll()`方法在错误情况下

对于算法的并发版本，我们测试了确定任务在不分成两个子任务的情况下可以处理的最大元素数量的大小参数的三个不同值。我们测试了 10、200 和 2,000。

我们使用 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）执行了测试，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比仅使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在具有四核处理器的计算机上执行了 10 次测试，并计算了这 10 次的平均执行时间。与其他示例一样，我们以毫秒为单位测量执行时间：

| 测试用例 | 串行 | 并发大小=10 | 并发大小=200 | 并发大小=2000 | 最佳 |
| --- | --- | --- | --- | --- | --- |
| **测试 1** | 1.177 | 8.124 | 4.547 | 4.073 | 串行 |
| **测试 2** | 95.237 | 157.412 | 34.581 | 35.691 | 并发 |
| **测试 3** | 66.616 | 41.916 | 74.829 | 37.140 | 并发 |
| **测试 4** | 0.540 | 25869.339 | 643.144 | 9.673 | 串行 |
| **测试 5** | 61.752 | 37.349 | 40.344 | 22.911 | 并发 |
| **测试 6** | 0.802 | 31663.607 | 231.440 | 7.706 | 串行 |

我们可以得出以下结论：

+   算法的串行版本在处理较少数量的元素时性能更好。

+   当我们需要处理所有元素或其中一部分元素时，并发版本的算法性能更好。

+   在错误情况下，串行版本的算法性能优于并发版本。当`size`参数的值较小时，并发版本在这种情况下性能非常差。

在这种情况下，并发并不总是能提高性能。

# 第三个示例 - 归并排序算法

归并排序算法是一种非常流行的排序算法，总是使用分而治之的技术实现，因此它是使用 Fork/Join 框架进行测试的一个很好的候选者。

为了实现归并排序算法，我们将未排序的列表分成一个元素的子列表。然后，我们合并这些未排序的子列表以产生有序的子列表，直到我们处理完所有子列表，我们只剩下原始列表，但其中所有元素都已排序。

为了使我们的算法的并发版本，我们使用了 Java 8 版本引入的新 Fork/Join 任务，`CountedCompleter`任务。这些任务最重要的特点是它们包括一个方法，在所有子任务完成执行时执行。

为了测试我们的实现，我们使用了**亚马逊产品共购买网络元数据**（您可以从[`snap.stanford.edu/data/amazon-meta.html`](https://snap.stanford.edu/data/amazon-meta.html)下载）。特别是，我们创建了一个包含 542,184 个产品销售排名的列表。我们将测试我们的算法版本，对这个产品列表进行排序，并将执行时间与`Arrays`类的`sort()`和`parallelSort()`方法进行比较。

## 共享类

正如我们之前提到的，我们已经构建了一个包含 542,184 个亚马逊产品的列表，其中包含每个产品的信息，包括 ID、标题、组、销售排名、评论数量、相似产品数量和产品所属的类别数量。我们已经实现了`AmazonMetaData`类来存储产品的信息。这个类声明了必要的属性和获取和设置它们的方法。这个类实现了`Comparable`接口来比较这个类的两个实例。我们想要按销售排名升序排序元素。为了实现`compare()`方法，我们使用`Long`类的`compare()`方法来比较这两个对象的销售排名，如下所示：

```java
    public int compareTo(AmazonMetaData other) {
        return Long.compare(this.getSalesrank(), other.getSalesrank());
    }
```

我们还实现了`AmazonMetaDataLoader`，它提供了`load()`方法。这个方法接收一个包含数据的文件路径作为参数，并返回一个包含所有产品信息的`AmazonMetaData`对象数组。

### 注意

我们不包括这些类的源代码，以便专注于 Fork/Join 框架的特性。

## 串行版本

我们在`SerialMergeSort`类中实现了归并排序算法的串行版本，该类实现了算法和`SerialMetaData`类，并提供了`main()`方法来测试算法。

### SerialMergeSort 类

`SerialMergeSort`类实现了归并排序算法的串行版本。它提供了`mergeSort()`方法，接收以下参数：

+   我们想要排序的包含所有数据的数组

+   方法必须处理的第一个元素（包括）

+   方法必须处理的最后一个元素（不包括）

如果方法只需要处理一个元素，它就返回。否则，它会对`mergeSort()`方法进行两次递归调用。第一次调用将处理元素的前一半，第二次调用将处理元素的后一半。最后，我们调用`merge()`方法来合并两半元素并得到一个排序好的元素列表：

```java
public void mergeSort (Comparable data[], int start, int end) {
    if (end-start < 2) { 
        return;
    }
    int middle = (end+start)>>>1;
    mergeSort(data,start,middle);
    mergeSort(data,middle,end);
    merge(data,start,middle,end);
}
```

我们使用`(end+start)>>>1`运算符来获取中间元素以分割数组。例如，如果你有 15 亿个元素（在现代内存芯片中并不那么不可能），它仍然适合 Java 数组。然而，*(end+start)/2*会溢出，导致数组为负数。你可以在[`googleresearch.blogspot.ru/2006/06/extra-extra-read-all-about-it-nearly.html`](http://googleresearch.blogspot.ru/2006/06/extra-extra-read-all-about-it-nearly.html)找到这个问题的详细解释。

`merge()`方法合并两个元素列表以获得一个排序好的列表。它接收以下参数：

+   我们想要排序的包含所有数据的数组

+   确定我们要合并和排序的数组的两部分（start-mid，mid-end）的三个元素（`start`、`mid`和`end`）

我们创建一个临时数组来对元素进行排序，对数组中的元素进行排序，处理列表的两部分，并将排序后的列表存储在原始数组的相同位置。检查以下代码：

```java
    private void merge(Comparable[] data, int start, int middle, int end) {
        int length=end-start+1;
        Comparable[] tmp=new Comparable[length];
        int i, j, index;
        i=start;
        j=middle;
        index=0;
        while ((i<middle) && (j<end)) {
            if (data[i].compareTo(data[j])<=0) {
                tmp[index]=data[i];
                i++;
            } else {
                tmp[index]=data[j];
                j++;
            }
            index++;
        }

        while (i<middle) {
            tmp[index]=data[i];
            i++;
            index++;
        }

        while (j<end) {
            tmp[index]=data[j];
            j++;
            index++;
        }

        for (index=0; index < (end-start); index++) {
            data[index+start]=tmp[index];
        }
    }
}
```

### SerialMetaData 类

`SerialMetaData`类提供了`main()`方法来测试算法。我们将执行每种排序算法 10 次，以计算平均执行时间。首先，我们从文件中加载数据并创建数组的副本：

```java
public class SerialMetaData {

    public static void main(String[] args) {
    for (int j=0; j<10; j++) {
        Path path = Paths.get("data","amazon-meta.csv");

        AmazonMetaData[] data = AmazonMetaDataLoader.load(path);
        AmazonMetaData data2[] = data.clone();
```

然后，我们使用`Arrays`类的`sort()`方法对第一个数组进行排序：

```java
        Date start, end;

        start = new Date();
        Arrays.sort(data);
        end = new Date();
        System.out.println("Execution Time Java Arrays.sort(): " + (end.getTime() - start.getTime()));
```

然后，我们使用自己实现的归并排序算法对第二个数组进行排序：

```java
        SerialMergeSort mySorter = new SerialMergeSort();
        start = new Date();
        mySorter.mergeSort(data2, 0, data2.length);
        end = new Date();
        System.out.println("Execution Time Java SerialMergeSort: " + (end.getTime() - start.getTime()));
```

最后，我们检查排序后的数组是否相同：

```java
        for (int i = 0; i < data.length; i++) {
            if (data[i].compareTo(data2[i]) != 0) {
                System.err.println("There's a difference is position " + i);
                System.exit(-1);
            }
        }
        System.out.println("Both arrays are equal");
    }
}
}
```

## 并发版本

正如我们之前提到的，我们将使用新的 Java 8 `CountedCompleter`类作为 Fork/Join 任务的基类。这个类提供了一个机制，当所有子任务都完成执行时执行一个方法。这就是`onCompletion()`方法。因此，我们使用`compute()`方法来划分数组，使用`onCompletion()`方法来将子列表合并成一个有序列表。

您要实现的并发解决方案有三个类：

+   扩展`CountedCompleter`类并实现执行归并排序算法的任务的`MergeSortTask`类

+   `ConcurrentMergeSort`任务启动第一个任务

+   提供`main()`方法来测试并发版本的归并排序算法的`ConcurrentMetaData`类

### `MergeSortTask`类

正如我们之前提到的，这个类实现了将执行归并排序算法的任务。这个类使用以下属性：

+   我们想要排序的数据数组

+   任务必须排序的数组的起始和结束位置

该类还有一个构造函数来初始化其参数：

```java
public class MergeSortTask extends CountedCompleter<Void> {

    private Comparable[] data;
    private int start, end;
    private int middle;

    public MergeSortTask(Comparable[] data, int start, int end,
            MergeSortTask parent) {
        super(parent);

        this.data = data;
        this.start = start;
        this.end = end;
    }
```

如果`compute()`方法中开始和结束索引之间的差大于或等于`1024`，我们将任务分成两个子任务来处理原始集合的两个子集。两个任务都使用`fork()`方法以异步方式将任务发送到`ForkJoinPool`。否则，我们执行`SerialMergeSorg.mergeSort()`来对数组的一部分进行排序（其中有`1024`个或更少的元素），然后调用`tryComplete()`方法。当子任务完成执行时，此方法将在内部调用`onCompletion()`方法。请查看以下代码：

```java
    @Override
    public void compute() {
        if (end - start >= 1024) {
                middle = (end+start)>>>1;
            MergeSortTask task1 = new MergeSortTask(data, start, middle, this);
            MergeSortTask task2 = new MergeSortTask(data, middle, end, this);
            addToPendingCount(1);
            task1.fork();
            task2.fork();
        } else {
            new SerialMergeSort().mergeSort(data, start, end);
            tryComplete();
        }
```

在我们的情况下，我们将使用`onCompletion()`方法来进行合并和排序操作以获得排序后的列表。一旦任务完成`onCompletion()`方法的执行，它会在其父任务上调用`tryComplete()`来尝试完成该任务。`onCompletion()`方法的源代码与算法的串行版本的`merge()`方法非常相似。请参考以下代码：

```java
    @Override
    public void onCompletion(CountedCompleter<?> caller) {
        if (middle==0) {
            return;
        }
        int length = end - start + 1;
        Comparable tmp[] = new Comparable[length];
        int i, j, index;
        i = start;
        j = middle;
        index = 0;
        while ((i < middle) && (j < end)) {
            if (data[i].compareTo(data[j]) <= 0) {
                tmp[index] = data[i];
                i++;
            } else {
                tmp[index] = data[j];
                j++;
            }
            index++;
        }
        while (i < middle) {
            tmp[index] = data[i];
            i++;
            index++;
        }
        while (j < end) {
            tmp[index] = data[j];
            j++;
            index++;
        }
        for (index = 0; index < (end - start); index++) {
            data[index + start] = tmp[index];
        }

    }
```

### `ConcurrentMergeSort`类

在并发版本中，这个类非常简单。它实现了`mergeSort()`方法，该方法接收要排序的数据数组以及开始索引（始终为 0）和结束索引（始终为数组的长度）作为参数来对数组进行排序。我们选择保持相同的接口而不是串行版本。

该方法创建一个新的`MergeSortTask`，使用`invoke()`方法将其发送到默认的`ForkJoinPool`，当任务完成执行并且数组已排序时返回。

```java
public class ConcurrentMergeSort {

    public void mergeSort (Comparable data[], int start, int end) {

        MergeSortTask task=new MergeSortTask(data, start, end,null);
        ForkJoinPool.commonPool().invoke(task);

    }
}
```

### 并发版本的`ConcurrentMetaData`类

`ConcurrentMetaData`类提供了`main()`方法来测试并发版本的归并排序算法。在我们的情况下，代码与`SerialMetaData`类的代码相同，但使用类的并发版本和`Arrays.parallelSort()`方法而不是`Arrays.sort()`方法，因此我们不包括该类的源代码。

## 比较两个版本

我们已经执行了我们的串行和并发版本的归并排序算法，并比较了它们之间以及与`Arrays.sort()`和`Arrays.parallelSort()`方法的执行时间。我们使用了 JMH 框架（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）来执行这四个版本，该框架允许您在 Java 中实现微基准测试。使用基准测试框架比简单地使用`currentTimeMillis()`或`nanoTime()`等方法来测量时间更好。我们在一个四核处理器的计算机上执行了 10 次，并计算了这 10 次的平均执行时间。这是我们在对包含 542,184 个对象的数据集进行排序时获得的执行时间（毫秒）：

|   | Arrays.sort() | 串行归并排序 | Arrays.parallelSort() | 并发归并排序 |
| --- | --- | --- | --- | --- |
| **执行时间（毫秒）** | 561.324 | 711.004 | 261.418 | 353.846 |

我们可以得出以下结论：

+   `Arrays.parallelSort()`方法获得了最佳结果。对于串行算法，`Arrays.sort()`方法获得的执行时间比我们的实现更好。

+   对于我们的实现，算法的并发版本比串行版本具有更好的性能。

我们可以使用加速比来比较归并排序算法的串行和并发版本：

![比较两个版本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-cncr-prog-java8/img/00018.jpeg)

# Fork/Join 框架的其他方法

在本章的三个示例中，我们使用了 Fork/Join 框架的类的许多方法，但还有其他有趣的方法您需要了解。

我们使用了`ForkJoinPool`类的`execute()`和`invoke()`方法将任务发送到池中。我们可以使用另一个名为`submit()`的方法。它们之间的主要区别在于，`execute()`方法将任务发送到`ForkJoinPool`并立即返回一个 void 值，`invoke()`方法将任务发送到`ForkJoinPool`并在任务完成执行时返回，`submit()`方法将任务发送到`ForkJoinPool`并立即返回一个`Future`对象以控制任务的状态并获取其结果。

在本章的所有示例中，我们使用了基于`ForkJoinTask`类的类，但您也可以使用基于`Runnable`和`Callable`接口的`ForkJoinPool`任务。为此，您可以使用接受`Runnable`对象、带有结果的`Runnable`对象和`Callable`对象的版本的`submit()`方法。

`ForkJoinTask`类提供了`get(long timeout, TimeUnit unit)`方法来获取任务返回的结果。该方法等待参数中指定的时间段以获取任务的结果。如果任务在此时间段之前完成执行，则方法返回结果。否则，它会抛出`TimeoutException`异常。

`ForkJoinTask`提供了`invoke()`方法的替代方法。它是`quietlyInvoke()`方法。两个版本之间的主要区别在于`invoke()`方法返回任务执行的结果，或者在必要时抛出任何异常。`quietlyInvoke()`方法不返回任务的结果，也不抛出任何异常。它类似于示例中使用的`quietlyJoin()`方法。

# 总结

分而治之的设计技术是解决不同类型问题的一种非常流行的方法。您将原始问题分解为较小的问题，然后将这些问题分解为更小的问题，直到我们有足够简单的问题直接解决它。在版本 7 中，Java 并发 API 引入了一种专门针对这些问题优化的`Executor`。它就是 Fork/Join 框架。它基于以下两个操作：

+   **fork**：这允许您创建一个新的子任务

+   **join**：这允许您等待子任务的完成并获取其结果

使用这些操作，Fork/Join 任务具有以下外观：

```java
if ( problem.size() > DEFAULT_SIZE) {
    childTask1=new Task();
    childTask2=new Task();
    childTask1.fork();
    childTask2.fork();
    childTaskResults1=childTask1.join();
    childTaskResults2=childTask2.join();
    taskResults=makeResults(childTaskResults1, childTaskResults2);
    return taskResults;
} else {
    taskResults=solveBasicProblem();
    return taskResults;
}
```

在本章中，您已经使用了 Fork/Join 框架解决了三种不同的问题，如 k 均值聚类算法、数据过滤算法和归并排序算法。

您已经使用了 API 提供的默认`ForkJoinPool`（这是 Java 8 版本的新功能），并创建了一个新的`ForkJoinPool`对象。您还使用了三种类型的`ForkJoinTask`：

+   `RecursiveAction`类，用作那些不返回结果的`ForkJoinTasks`的基类。

+   `RecursiveTask`类，用作那些返回结果的`ForkJoinTasks`的基类。

+   `CountedCompleter`类，引入于 Java 8，并用作那些需要在所有子任务完成执行时执行方法或启动另一个任务的`ForkJoinTasks`的基类。

在下一章中，您将学习如何使用新的 Java 8 **并行流**来使用 MapReduce 编程技术，以获得处理非常大数据集的最佳性能。
