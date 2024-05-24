# Jenkins 持续集成秘籍（三）

> 原文：[`zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7`](https://zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用指标提高质量

在本章中，我们将涵盖以下内容：

+   通过 Sloccount 估算你的项目价值

+   通过代码覆盖率查找“臭味”代码

+   激活更多的 PMD 规则集

+   创建自定义 PMD 规则

+   使用 FindBugs 查找错误

+   启用额外的 FindBug 规则

+   使用 FindBugs 查找安全缺陷

+   验证 HTML 的有效性

+   使用 JavaNCSS 进行报告

+   使用外部 pom.xml 文件检查样式

+   伪造 Checkstyle 结果

+   将 Jenkins 与 SonarQube 集成

+   使用 R 插件分析项目数据

    ### 注意

    一些构建文件和代码有故意的错误，比如糟糕的命名约定、糟糕的编码结构或平台特定的编码。

    这些缺陷存在是为了让 Jenkins 有一个测试的目标。

# 介绍

本章探讨了使用 Jenkins 插件显示代码指标和失败构建。自动化降低成本并提高一致性。这个过程不会感到疲倦。如果你在项目开始之前确定了成功和失败的标准，那么这将减少发布会议中的主观辩论。

在 2002 年，NIST 估计软件缺陷每年给美国造成了大约 600 亿美元的损失 ([`www.abeacha.com/NIST_press_release_bugs_cost.htm`](http://www.abeacha.com/NIST_press_release_bugs_cost.htm))。预计这个成本已经大大增加。

为了节省成本并提高质量，你需要尽早在软件生命周期中消除缺陷。Jenkins 测试自动化创建了一张测量的安全网。另一个关键的好处是，一旦你添加了测试，就很容易为其他项目开发类似的测试。

Jenkins 与最佳实践（如**测试驱动开发**（**TDD**）或**行为驱动开发**（**BDD**））配合得很好。使用 TDD，你首先编写失败的测试，然后构建通过测试所需的功能。使用 BDD，项目团队以行为的形式编写测试描述。这使得描述对更广泛的受众可理解。更广泛的受众对实施细节具有更多的影响。

回归测试增加了重构软件时没有破坏代码的信心。代码测试覆盖率越高，信心越足。*通过代码覆盖率查找“有异味”的代码*的方法向您展示了如何使用 Cobertura（[`cobertura.github.io/cobertura/`](https://cobertura.github.io/cobertura/)）来测量覆盖率。类似的框架还有 Emma（[`emma.sourceforge.net/`](http://emma.sourceforge.net/)）。您还会在静态代码审查方面找到 PMD 和 FindBugs 的相关方法。静态意味着您可以查看代码而无需运行它。PMD 检查`.java`文件是否存在特定的错误模式。使用 PMD 规则设计器编写新的错误检测规则相对较容易。FindBugs 扫描编译后的`.class`文件；您可以直接查看应用的`.jar`文件。FindBugs 规则准确，大多数指向实际缺陷。在本章中，您将使用 FindBugs 搜索安全缺陷，并使用 PMD 搜索设计规则违例。

本章还提到了使用已知缺陷的 Java 类。我们将使用这些类来检查测试工具的价值。这与病毒检查器的基准类似，病毒检查器会解析具有已知病毒签名的文件。注入已知缺陷的优势在于您可以了解到违反的规则。这是收集项目中发现的实际缺陷并对其进行特征化和重复利用的好方法。考虑将自己的类添加到项目中，以查看 QA 过程是否能够捕捉到缺陷。

良好的文档和源代码结构有助于代码的可维护性和可读性。Sun 编码规范强制执行跨项目的一致标准。在本章中，您将使用 Checkstyle 和 JavaNCSS 来将您的源代码与 Sun 编码规范进行比较（[`www.oracle.com/technetwork/java/codeconventions-150003.pdf`](http://www.oracle.com/technetwork/java/codeconventions-150003.pdf)）。

Jenkins 插件生成的结果可以通过违例插件（[`wiki.jenkins-ci.org/display/JENKINS/Violations`](https://wiki.jenkins-ci.org/display/JENKINS/Violations)）聚合为一个报告。还有其他针对特定工具的插件，例如 PMD 或 FindBugs 插件。这些插件由分析收集器插件支持（[`wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin)），该插件将其他报告聚合为一个统一的整体。可以通过 Portlets 仪表板插件显示单个插件报告，该插件在第四章 *通过 Jenkins 进行通信*中讨论过 *使用仪表板视图插件节约屏幕空间*。

Jenkins 不仅限于测试 Java；许多插件如 SLOCCount 或 DRY 插件（它可以发现代码的重复）是与语言无关的。甚至还有针对.NET 中的 NUnit 测试或其他语言的编译的特定支持。

### 注意

NUnit、JUnit、RUnit 和几个其他单元测试框架都遵循 xUnit 标准。详细信息请参阅维基百科条目：[`en.wikipedia.org/wiki/XUnit`](http://en.wikipedia.org/wiki/XUnit)

如果你缺少特定功能，你总是可以按照第七章 *插件探索*中的详细说明构建自己的 Jenkins 插件。

有许多关于软件度量的好介绍。这些包括关于指标细节的维基书籍（[`en.wikibooks.org/wiki/Introduction_to_Software_Engineering/Quality/Metrics`](http://en.wikibooks.org/wiki/Introduction_to_Software_Engineering/Quality/Metrics)）和 Diomidis Spinellis 撰写的一本写得很好的书籍*Code Quality: The Open Source Perspective*。

在本章的*将 Jenkins 与 SonarQube 集成*中，你将把 Jenkins 项目链接到 Sonar 报告上。Sonar 是一个专业工具，用于收集软件指标并将其分解为可理解的报告。Sonar 详细说明了项目的质量。它使用了一系列指标，包括本章中提到的 FindBugs 和 PMD 等工具的结果。项目本身正在快速发展。考虑使用 Jenkins 进行早期警告并发现明显的缺陷，比如糟糕的提交。然后你可以使用 Sonar 进行更深入的审查。

最后，你将运行解析项目中所有文件并报告简单指标的 R 代码。这个自定义过程很容易根据 R 语言中包含的丰富的统计包进行复杂的分析。

### 注意

在撰写本文时，FindBugs 和 PMD Jenkins 插件都需要特定版本的 Maven。作为管理员，你可以通过主配置屏幕（`http://hostname/configure`）下的**Maven**部分，通过按下**添加 Maven**按钮来自动安装 Maven 版本。稍后当你创建一个任务时，Jenkins 会给你选择 Maven 版本的选项。

当处理多模块的 Maven 项目时，Maven 插件会生成一系列结果。Maven 项目类型严格假设结果存储在常规位置，但这并不总是一致的。对于自由样式项目，你可以明确告诉 Jenkins 插件在哪里找到结果，使用与 Ant 文件集一致的正则表达式（[`ant.apache.org/manual/Types/fileset.html`](http://ant.apache.org/manual/Types/fileset.html)）。

# 通过 sloccount 估算你项目的价值

了解项目价值的一种方法是计算项目中的代码行数并在代码语言之间进行计数。 由 Dr. David Wheeler（[`www.dwheeler.com/sloccount/`](http://www.dwheeler.com/sloccount/)）编写的 SLOCCount，发音为“sloc-count”，是一个用于计算潜在大型软件系统中物理源代码行（SLOC）的命令行工具套件。 通过这些指标，您可以估算编写代码和估算开发成本需要多少小时。

## 准备工作

安装 SLOCCount 插件（[`wiki.jenkins-ci.org/display/JENKINS/SLOCCount+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/SLOCCount+Plugin)）。 为此配方代码创建一个新目录。 如 [`www.dwheeler.com/sloccount`](http://www.dwheeler.com/sloccount) 所述，在 Jenkins 实例上安装 SLOCCount。 如果您正在运行 Debian 操作系统，则以下安装命令将起作用：

```
sudo apt-get install sloccount

```

有关如何在其他系统上安装 SLOCCount 的详细信息，请查看：[`www.dwheeler.com/sloccount/sloccount.html`](http://www.dwheeler.com/sloccount/sloccount.html)

## 如何操作...

1.  创建一个自由风格的项目并将其命名为`ch5.quality.sloccount`。 将`SLOCCOUNT REPORT Project`添加为描述。

1.  在**源代码管理**部分，勾选**Subversion**，添加**存储库 URL**：[`source.sakaiproject.org/svn/shortenedurl/trunk`](https://source.sakaiproject.org/svn/shortenedurl/trunk)。

1.  在**构建**部分中，从**添加构建**步骤中选择**执行 shell**。 添加`/usr/bin/sloccount --duplicates --wide --details . >./sloccount.sc 命令`。

1.  在**后构建操作**部分，检查**发布 SLOCCount 分析结果**，添加到文本输入**SLOCCount 报告**，`sloccount.sc`。

1.  单击**保存**。

运行任务并查看详情。 您现在将看到相关语言的概述，如下图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_01.jpg)

在顶级，您还将看到随时间推移代码每种语言的代码行数的时间序列。 这对需要估算完成项目所需资源的经理非常有用：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_02.jpg)

报告还允许您深入研究特定文件。 文件越大，开发人员就越容易迷失代码的含义。 如果您看到一个特别大的文件，那么值得审查，如下图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_03.jpg)

### 注

要将您生成的报告与更广泛的 Sakai 项目进行比较，请访问[`www.openhub.net/p/sakai#`](https://www.openhub.net/p/sakai#)。

## 工作原理...

该秘籍引入了实际代码，这是一个基于 Java 的服务，用于生成缩短的 URL（[`confluence.sakaiproject.org/display/SHRTURL`](https://confluence.sakaiproject.org/display/SHRTURL)）。Jenkins 插件将 SLOCCount 生成的结果转换为详细信息。报告分为四个标签页的表格，按文件、模块、文件夹和语言进行汇总和排序。通过这些信息，您可以估计从头开始重建项目所需的工作程度。

工作描述包含指向 open hub ([`blog.openhub.net/2014/07/black-duck-open-hub/`](http://blog.openhub.net/2014/07/black-duck-open-hub/)) 的 URL，这是一个值得信赖的第三方服务。Open hub 是一个众所周知的服务，其隐私规则有着良好的描述（[`blog.openhub.net/privacy/`](http://blog.openhub.net/privacy/)）。然而，如果您不完全信任第三方服务的声誉，那么就不要通过 Jenkins 描述进行链接。

您可以通过访问[`www.openhub.net/p/sakai#`](https://www.openhub.net/p/sakai#)了解有关 Sakai 学习管理系统的信息。缩短的 URL 服务只是其中的一小部分。综合统计数据可以让访问者更好地了解更广泛的背景，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_04.jpg)

## 还有更多...

还有一些细节需要考虑。

### 软件成本估算

SLOCCount 使用 COCOMO 模型 ([`en.wikipedia.org/wiki/COCOMO`](http://en.wikipedia.org/wiki/COCOMO)) 来估算项目成本。您不会在 Jenkins 报告中看到此内容，但如果您从命令行运行 SLOCCount，您可以生成估算成本。

成本估计为 `effort * personcost * overhead`。

随着时间推移，变化最大的元素是人力成本（以美元计）。您可以使用命令行参数`–personcost`来更改该值。

### 再见 Google 代码搜索；你好 code.ohoh.net

谷歌宣布已关闭其源代码搜索引擎。幸运的是，[code.ohloh.net](http://code.ohloh.net)（之前是[koders.com](http://koders.com)）另一个可行的搜索引擎，宣布将提供对[ohloh.net](http://ohloh.net)中描述的代码库的覆盖。使用这个搜索引擎，您将能够审查大量的开源项目。该搜索引擎补充了您可以在您喜爱的在线存储库（如 GitHub 和 Bitbucket）中搜索的代码。

## 另请参阅

+   *通过 Jenkins 进行通信* 的第四章中的 *使用 Google Analytics 了解您的受众* 秘籍

+   *使用 R 插件分析项目数据* 秘籍

# 通过代码覆盖寻找“臭味”代码

本秘籍使用 **Cobertura** ([`cobertura.sourceforge.net/`](http://cobertura.sourceforge.net/)) 来查找未被单元测试覆盖的代码。

没有持续的实践，编写单元测试将变得像向`stdout`写入调试信息一样困难。大多数流行的 Java 特定 IDE 都内置支持运行单元测试。Maven 将它们作为测试目标的一部分运行。如果您的代码没有回归测试，那么在重构过程中代码更容易中断。测量代码覆盖率可用于搜索未测试代码的热点。

### 注

欲了解更多信息，您可以查看：[`onjava.com/onjava/2007/03/02/statement-branch-and-path-coverage-testing-in-java.html`](http://onjava.com/onjava/2007/03/02/statement-branch-and-path-coverage-testing-in-java.html)。

## 准备工作

安装 Cobertura 代码覆盖插件 ([`wiki.jenkins-ci.org/display/JENKINS/Cobertura+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Cobertura+Plugin))。

## 怎么做...

1.  使用以下命令生成模板项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.coverage -DartifactId=coverage -DarchetypeArtifactId=maven-archetype-quickstart -Dversion=1.0-SNAPSHOT 

    ```

1.  使用以下命令测试未修改项目的代码覆盖率：

    ```
    mvn clean cobertura:cobertura

    ```

1.  审查 Maven 的输出。它看起来类似于以下输出：

    ```
    -------------------------------------------------------
    T E S T S
    -------------------------------------------------------
    Running nl.berg.packt.coverage.AppTest
    Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time
    elapsed: 0.036 sec

    Results :
    Tests run: 1, Failures: 0, Errors: 0, Skipped: 0

    [INFO] [cobertura:cobertura {execution: default-cli}]
    [INFO] Cobertura 1.9.4.1 - GNU GPL License (NO WARRANTY) –
    Cobertura: Loaded information on 1 classes.
    Report time: 107ms
    [INFO] Cobertura Report generation was successful.

    ```

1.  在网络浏览器中，查看`/target/site/cobertura/index.html`。请注意，如下屏幕截图所示，没有代码覆盖率：![怎么做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_05.jpg)

1.  将以下内容添加到`src/main/java/nl/berg/packt/coverage/Dicey.java`：

    ```
    package nl.berg.packt.coverage;
    import java.util.Random;
    public class Dicey {
      private Random generator;
      public Dicey(){
        this.generator = new Random();
        throwDice();
      }

      private int throwDice() {
        int value = generator.nextInt(6) + 1;
        if (value > 3){
          System.out.println("Dice > 3");
        }else{
          System.out.println("Dice < 4");
        }
        return value;
      }
    }
    ```

1.  修改`src/test/java/nl/berg/packt/coverage/AppTest.java`以通过更改`testApp()`方法来实例化一个新的 `Dicey` 对象：

    ```
    Public void testApp(){
      new Dicey();
      assertTrue( true );
    }
    ```

1.  使用以下命令测试 JUnit 测试的代码覆盖率：

    ```
    mvn clean cobertura:cobertura

    ```

1.  查看 Maven 输出，注意 `Dicey` 构造函数内部的 `println` 也已包含在内：

    ```
    -------------------------------------------------------
    T E S T S
    -------------------------------------------------------
    Running nl.berg.packt.coverage.AppTestDice < 4 Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.033 sec
    ```

1.  在网络浏览器中打开`view /target/site/cobertura/index.html`。您的项目现在具有代码覆盖率，并且您可以看到尚未调用的代码行，如下屏幕截图所示：![怎么做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_06.jpg)

1.  将以下**构建**部分添加到您的`pom.xml`中：

    ```
    <build>
      <plugins>
        <plugin>
          <groupId>org.codehaus.mojo</groupId>
          <artifactId>cobertura-maven-plugin</artifactId>
            <version>2.6</version>
            <configuration>
            <formats>
              <format>xml</format>
              <format>html</format>
            </formats>
          </configuration>
        </plugin>
      </plugins>
    </build>
    ```

1.  使用以下命令测试 JUnit 测试的代码覆盖率：

    ```
    mvn clean cobertura:cobertura

    ```

1.  访问位置`target/site/cobertura`，注意现在结果也存储在`coverage.xml`中。

1.  运行`mvn clean`以删除目标目录。

1.  将 Maven 项目添加到您的 Subversion 仓库中。

1.  创建一个名为`ch5.quality.coverage`的新 **Maven** 项目。

1.  在**源代码管理**部分中，勾选**Subversion**并添加您的存储库位置。

1.  在**构建**部分下的**目标和选项**中添加`clean cobertura:cobertura`。

1.  在**后期构建操作**部分中勾选**发布 Cobertura 覆盖率报告**。对于 Cobertura xml 报告模式输入，添加`**/target/site/cobertura/coverage.xml`。

1.  点击**保存**。

1.  点击两次**立即构建**以生成工作的趋势，然后审查结果。

趋势图是类，条件（例如 `if` 语句的分支），文件，代码行，方法和包的百分比的线性图。Jenkins 使用不同颜色的线显示每种类型，如下屏幕截图所示：

![怎么做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_24.jpg)

## 它是如何工作的...

Cobertura 在编译期间对 Java 字节码进行仪器化。Maven 插件会生成 HTML 和 XML 报告。HTML 报告允许你从命令行快速查看代码状态。XML 报告需要 Jenkins 插件解析。

你将插件配置放在了**build**部分而不是报告部分，以避免运行带有额外阶段的**site**目标。

自由样式项目被用来使 Cobertura 插件捡起多个 XML 报告。这是由文件集 `**/target/site/cobertura/coverage.xml` 定义的，该文件集表示工作空间下任何 `target/site/cobertura` 目录下的任何报告都称为 `coverage.xml`。

Maven 运行了 `clean cobertura:cobertura`。`clean` 目标会删除所有的 target 目录，包括以前编译和仪器化的代码。`cobertura:cobertura` 目标编译和仪器化代码，运行单元测试，然后生成报告。

`testApp` 单元测试调用了 `Dicey` 类的构造函数。构造函数随机生成从 1 到 6 的数字，模拟骰子，并在一个 `if` 语句的两个分支中进行选择。cobertura 报告允许你放大到源代码并发现做出的选择。该报告非常适用于识别遗漏的测试。如果你重构代码，那么在这些区域将没有单元测试，以便在代码意外更改行为时发现。该报告还擅长发现比周围环境更复杂的代码。代码越复杂，越难理解，也越容易引入错误。

以下文章是如何使用 cobertura 以及生成的指标背后含义的绝佳示例：[`www.ibm.com/developerworks/java/library/j-cq01316/index.html?ca=drs`](http://www.ibm.com/developerworks/java/library/j-cq01316/index.html?ca=drs)。

## 更多内容...

另一个开源工具替代品是 Emma ([`emma.sourceforge.net`](http://emma.sourceforge.net))。Emma 还有一个相关的 Jenkins 插件 [`wiki.jenkins-ci.org/display/JENKINS/Emma+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Emma+Plugin)。在 Maven 中，你不需要在 `pom.xml` 文件中添加任何配置。你只需运行目标 `clean emma:emma package` 并将 Jenkins 插件指向结果。

### 注意

另一个替代框架是 Jacoco ([`www.eclemma.org/index.html`](http://www.eclemma.org/index.html))。Jacoco 被设计为 Emma 的一个后代。你可以在这里找到其 Jenkins 插件的完整描述：[`wiki.jenkins-ci.org/display/JENKINS/JaCoCo+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/JaCoCo+Plugin)。

# 激活更多的 PMD 规则集

PMD 有规则来捕获特定的错误。它将这些规则捆绑到规则集中。例如，有一个主题是关于 Android 编程的规则集，另一个是关于代码大小或设计的规则集。默认情况下，测量了三个非有争议的 PMD 规则集：

+   **基础**：此规则集包含每个开发人员都应遵循的明显实践，例如不要忽略已捕获的异常。

+   **未使用的代码**：此规则集可查找从未使用过的代码以及可消除的行，避免浪费并增加可读性。

+   **导入**：此规则集可发现不必要的导入。

此示例向您展示如何启用更多规则。主要风险是额外规则会生成大量误报，使真正的缺陷难以辨别。好处是您将捕获更广泛的缺陷，其中一些在进入生产环境后会造成严重后果。

## 准备工作

安装 Jenkins PMD 插件 ([`wiki.jenkins-ci.org/display/JENKINS/PMD+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/PMD+Plugin))。

### 提示

**Jenkins bug [Jenkins-22252]**

[`issues.jenkins-ci.org/browse/JENKINS-22252`](https://issues.jenkins-ci.org/browse/JENKINS-22252)

在撰写本文时，Jenkins 中的 Maven 3.2.1 与 PMD 插件不兼容。短期解决方案是在构建中使用 Maven 3.0.5。但是，到您阅读此警告时，我期望该问题已得到解决。

您可以从 Jenkins 的主配置屏幕 (`http://localhost:8080/configure`) 自动安装不同版本的 Java、Maven 或 Ant。

## 如何做...

1.  使用以下命令生成模板项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.pmd -DartifactId=pmd -DarchetypeArtifactId=maven-archetype-quickstart -Dversion=1.0-SNAPSHOT

    ```

1.  使用以下内容将 Java 类 `src/main/java/nl/berg/packt/pmd/PMDCandle.java` 添加到项目中：

    ```
    package nl.berg.packt.pmd;
    import java.util.Date;
    public class PMDCandle {
      private String MyIP = "123.123.123.123";
      public void dontDontDoThisInYoourCode(){
        System.out.println("Logging Framework please"); 
        try {
          int x =5;
        }catch(Exception e){} String myString=null;
        if (myString.contentEquals("NPE here"));
      }
    }
    ```

1.  使用以下命令测试您的未修改项目：

    ```
    mvn clean pmd:pmd

    ```

1.  查看目录 `target`，您会注意到结果 `java-basic.xml`、`java-imports.xml`、`java-unusedcode.xml`，以及聚合结果 `pmd.xml`。

1.  在 web 浏览器中查看文件 `target/site/pmd.html`。

1.  将以下报告部分添加到您的 `pom.xml` 文件中：

    ```
    <reporting>
      <plugins>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-jxr-plugin</artifactId>
          <version>2.3</version>
        </plugin>
       <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-pmd-plugin</artifactId>
      <version>3.2</version>
      <configuration>
      <targetJdk>1.6</targetJdk>
      <format>xml</format>
      <linkXref>true</linkXref>
      <minimumTokens>100</minimumTokens>
      <rulesets>
        <ruleset>/rulesets/basic.xml</ruleset>
        <ruleset>/rulesets/braces.xml</ruleset>
        <ruleset>/rulesets/imports.xml</ruleset>
        <ruleset>/rulesets/logging-java.xml</ruleset>
        <ruleset>/rulesets/naming.xml</ruleset>
        <ruleset>/rulesets/optimizations.xml</ruleset>
        <ruleset>/rulesets/strings.xml</ruleset>
        <ruleset>/rulesets/sunsecure.xml</ruleset>
        <ruleset>/rulesets/unusedcode.xml</ruleset>
      </rulesets>
      </configuration>
        </plugin>
      </plugins>
    </reporting>
    ```

1.  使用以下命令测试您的项目：

    ```
    mvn clean pmd:pmd

    ```

1.  在 web 浏览器中查看文件 `target/site/pmd.html`，注意到现在发现了额外的违规行为。这是由于在 `pom.xml` 文件中添加了额外规则造成的。

1.  运行 `mvn clean` 来删除 `target` 目录。

1.  将源代码添加到您的 Subversion 仓库。

1.  创建一个名为 `ch5.quality.pmd` 的新 **Maven** Jenkins 作业，包含以下详细信息：

    +   **源代码管理** | **Subversion**：您的仓库

    +   **构建** | **目标和选项**：`clean pmd:pmd`

    +   **构建设置**：**发布 PMD 分析结果**

1.  单击 **保存**。

1.  单击 **立即构建** 两次以生成趋势。查看结果。

顶层报告汇总了缺陷数量及其优先级。它还提到了一些详细信息，如下图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_07.jpg)

你可以放大代码并查看高亮显示的区域以查找缺陷：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_08.jpg)

## 工作原理...

Maven PMD 插件测试了一系列规则集。当你从 PMD 网站下载二进制包（[`pmd.sourceforge.net/`](http://pmd.sourceforge.net/)）时，你可以通过列出 `pmd.jar` 文件的内容找到规则集的路径。在 *NIX 系统下执行此操作的命令是：

```
unzip –l pmd-version.jar | grep rulesets

```

你添加了一个标准的基准，一个具有已知缺陷的 Java 类，触发 PMD 警告。例如，以下两行代码中有多个缺陷：

```
String myString=null;
if (myString.contentEquals("NPE here"));
```

最重要的缺陷是 Java 程序员需要首先放置文本来避免 `NullPointerException`，例如：

```
"NPE here".contentEquals(myString)
```

当 `myString` 为 `null` 时，首先返回 false。`if` 语句周围缺少大括号是一个问题。当触发 `if` 语句时，同样适用于缺少要运行的命令。

另一个微不足道的例子是将基础设施细节硬编码到你的源代码中。例如，密码、IP 地址和用户名。最好将细节移到仅驻留在部署服务器上的属性文件中。以下一行测试 PMD 是否能够发现这种类型的缺陷：

```
private String MyIP = "123.123.123.123";
```

FindBugs 和 PMD 都有自己的一套 bug 模式检测器。两者都不会捕获所有类型的缺陷。因此，值得运行这两个工具来捕获最广泛范围的缺陷。有关这两款产品的评论，请访问[`www.freesoftwaremagazine.com/articles/destroy_annoying_bugs_part_1`](http://www.freesoftwaremagazine.com/articles/destroy_annoying_bugs_part_1)。

你可能会对其他几个静态代码审查工具感兴趣，例如 QJPro ([`qjpro.sourceforge.net/`](http://qjpro.sourceforge.net/)) 和 Jlint ([`jlint.sourceforge.net/`](http://jlint.sourceforge.net/))。

## 还有更多...

Out-of-the-box，PMD 测试了一组合理的 bug 缺陷；然而，每个项目都是不同的，你需要进行调整。

### 减少 PMD 规则集的速率

重要的是要理解规则集的重要性，并塑造 Maven 配置，仅包括有用的规则。如果你不为一个中等规模的项目做这个，报告将包含数千个违规行为，隐藏了真正的缺陷。然后报告将需要时间在你的网络浏览器中渲染。考虑启用一个长列表的规则，只有当你想要使用体积作为项目成熟度的指标时。

要减少，排除代码的部分并系统地清理报告的区域。

### 注意

你可以在这里找到当前的 PMD 规则集：[`pmd.sourceforge.net/rules/index.html`](http://pmd.sourceforge.net/rules/index.html)

### 不要重复自己的原则

剪切和粘贴编程，克隆，然后修改代码会导致重构的噩梦。如果代码没有正确封装，很容易在代码库中散落着略有不同的代码片段。如果你想要删除已知的缺陷，那将需要额外的工作。

PMD 通过查找重复代码来支持不要重复自己（DRY）原则。触发点通过 `minimumTokens` 标签进行配置。然而，PMD 插件不会拾取结果（存储在 `cpd.xml` 中）。您需要安装和配置 DRY 插件（[`wiki.jenkins-ci.org/display/JENKINS/DRY+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/DRY+Plugin)）或 Jenkins 违规插件。

### 注意

如果您从其网站下载了 PMD 二进制文件（[`sourceforge.net/projects/pmd/files/pmd/`](http://sourceforge.net/projects/pmd/files/pmd/)），那么在 bin 目录中，您会找到 `cpdgui`。这是一个允许您在源代码中探索重复的 Java swing 应用程序。

## 参见

+   *创建自定义 PMD 规则* 配方

+   *使用 R 插件分析项目数据* 配方

# 创建自定义 PMD 规则

与其他静态代码审查工具相比，PMD 有两个额外的功能。第一个是 `cpdgui` 工具，允许您查找从代码库的一个部分复制粘贴到另一个部分的代码。第二个，也是我们将在这个配方中探索的，是使用 Xpath 为 Java 源代码设计自定义 bug 发现规则的能力。

## 准备工作

确保您已安装了 Jenkins PMD 插件（[`wiki.jenkins-ci.org/display/JENKINS/PMD+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/PMD+Plugin)）。从 [`pmd.sourceforge.net`](http://pmd.sourceforge.net) 下载并解压 PMD 发行版。访问 PMD bin 目录，并验证您是否具有启动脚本 `run.sh designer` 和 `designer.bat`。

## 如何做...

1.  使用以下命令从命令行创建一个 Maven 项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.pmdrule -DartifactId=pmd_design -DarchetypeArtifactId=maven-archetype-quickstart -Dversion=1.0-SNAPSHOT

    ```

1.  在 `pom.xml` 文件中，`</project>` 标记之前添加一个 `reporting` 部分，内容如下：

    ```
    <reporting>
      <plugins>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-jxr-plugin</artifactId>
          <version>2.1</version>
        </plugin>
      <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-pmd-plugin</artifactId>
      <version>2.6</version>
      <configuration>
      <targetJdk>1.6</targetJdk>
      <format>xml</format>
      <rulesets>
        <ruleset>password_ruleset.xml</ruleset>
      </rulesets>
      </configuration>
        </plugin>
      </plugins>
    </reporting>
    ```

    ### 注意

    此配方仅适用于版本 2.6。

1.  在顶层目录下，创建名为 `password_ruleset.xml` 的文件，内容如下：

    ```
    <?xml version="1.0"?>
    <ruleset name="STUPID PASSWORDS ruleset"

      xsi:schemaLocation="http://pmd.sf.net/ruleset/1.0.0 http://pmd.sf.net/ruleset_xml_schema.xsd"
      xsi:noNamespaceSchemaLocation="http://pmd.sf.net/ruleset_xml_schema.xsd">
      <description>
      Lets find stupid password examples
      </description>
    </ruleset>
    ```

1.  编辑 `src/main/java/nl/berg/packt/pmdrule/App.java`，使得主方法为：

    ```
    public static void main( String[] args )
    {
      System.out.println( "Hello World!" );
      String PASSWORD="secret";
    }
    ```

1.  根据您的操作系统，使用启动脚本 `bin/run.sh designer` 或 `bin/designer.bat` 运行 pmd designer。

1.  点击屏幕左上角的 **JDK** 选项，选择 **JDK 1.6** 作为 Java 版本。

1.  在 **源代码** 文本区域中，添加要针对测试的示例代码。在本例中：

    ```
    public class RuleTest {
      static final String PASSWORD="secret";
    }
    ```

1.  对于 **查询（如果有的话）** 文本区域，添加：

    ```
    //VariableDeclaratorId[@Image='PASSWORD']
    ```

1.  点击 **Go**。你现在会看到结果 **第 2 行第 20 列的 ASTVariableDeclarorID**，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_09.jpg)

1.  在屏幕顶部的 **操作** 菜单选项下，选择 **创建规则 XML**。添加以下值：

    +   **规则名称**：无密码

    +   **规则消息**：如果我们看到密码，我们应该标记

    +   **规则描述**：让我们找到愚蠢的密码示例

1.  点击 **创建规则 XML**。生成的 XML 应该有一个类似于的片段：

    ```
    <rule  name="NO_PASSWORD"
      message="If we see a PASSWORD we should flag"
      class="net.sourceforge.pmd.rules.XPathRule">
      <description>
      If we see a PASSWORD we should flag
      </description>
      <properties>
        <property name="xpath">
        <value>
    <![CDATA[
    //VariableDeclaratorId[@Image='PASSWORD']

    ]]>
        </value>
        </property>
      </properties>
      <priority>3</priority>
      <example>
    <![CDATA[
    public class RuleTest {
        static final String PASSWORD="secret";
    }
    ]]>
      </example>
    </rule>
    ```

    ![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_18.jpg)

1.  将生成的代码复制并粘贴到`password_ruleset.xml`中的`</ruleset>`之前。

1.  将项目提交到您的 Subversion 存储库。

1.  在 Jenkins 中，创建一个名为`ch5.quality.pmdrule`的**Maven**作业。

1.  在**源代码管理**部分，勾选**Subversion**，并为**存储库 URL**添加您的 Subversion 存储库位置。

1.  在**构建**部分的**目标和选项**中，将值设置为`clean site`。

1.  在**构建设置**部分，勾选**发布 PMD 分析结果**。

1.  点击**保存**。

1.  运行作业。

1.  查看**PMD 警告**链接，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_25.jpg)

## 工作原理是什么...

PMD 分析源代码并将其分解为称为抽象语法树（AST）的元数据（[`onjava.com/pub/a/onjava/2003/02/12/static_analysis.html`](http://onjava.com/pub/a/onjava/2003/02/12/static_analysis.html)）。PMD 能够使用 Xpath 规则在 AST 中搜索模式。W3Schools 提供了 Xpath 的简明介绍（[`www.w3schools.com/xpath/`](http://www.w3schools.com/xpath/)）。设计工具使您能够编写 Xpath 规则，然后针对源代码示例测试您的规则。为了可读性，测试代码中应该只包含必要的细节。然后将规则存储在 XML 中。

要将 XML 规则打包在一起，你必须将规则添加为`<ruleset>`标记的一部分。

Maven PMD 插件有能力从其类路径、本地文件系统或通过 HTTP 协议从远程服务器读取规则集。您通过添加配置选项添加了您的规则集：

```
<ruleset>password_ruleset.xml</ruleset>
```

如果你建立了一套规则集，应该将所有规则都放入一个项目中以便管理。

您还可以根据已有规则创建自己的自定义规则集，提取您喜欢的错误检测模式。这可以通过带有指向已知规则的`<rule>`标记来实现，例如，以下从`imports.xml`规则集中提取了`DuplicateImports`规则：

```
<rule ref="rulesets/imports.xml/DuplicateImports"/>
```

本示例生成的规则测试了名称为`PASSWORD`的变量。我们在真实项目中多次触发了该规则。

我们将 Maven PMD 插件的版本锁定为 2.6，以确保在插件的将来发布版本后仍然可以使用本示例。

### 注意

PMD 主页是了解 Xpath 规则可能性的好地方。它包含了规则集的描述和详细信息，例如，日志规则；请参阅[`pmd.sourceforge.net/pmd-4.3.0/rules/logging-java.html`](http://pmd.sourceforge.net/pmd-4.3.0/rules/logging-java.html)。

## 还有更多...

如果静态代码审查工具能够就如何修复代码提出建议将是非常有效的。然而，这有点危险，因为检测器并不总是准确的。作为一个实验，我编写了一个小型的 Perl 脚本，首先修复字面量，然后删除一些资源的浪费。这段代码是一个概念验证，因此不能保证正确运行。它的好处在于简洁，参见：

[`source.sakaiproject.org/contrib/qa/trunk/static/cleanup/easy_wins_find_java.pl`](https://source.sakaiproject.org/contrib/qa/trunk/static/cleanup/easy_wins_find_java.pl)

## 另请参阅

+   *激活更多的 PMD 规则集* 示例

# 使用 FindBugs 查找错误

在静态代码审查工具发现的缺陷数量中很容易迷失方向。另一个质量保证攻击模式是逐个清理缺陷包，集中开发者的时间在最常用的功能上。

这个示例将向您展示如何为特定包生成和报告 FindBugs 发现的缺陷。

## 准备工作

安装 Jenkins FindBugs 插件 ([`wiki.jenkins-ci.org/display/JENKINS/FindBugs+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/FindBugs+Plugin))。

### 提示

**Java 版本**

FindBugs 插件版本 3 需要 Java 7 或更高版本。

## 如何操作...

1.  从命令行创建一个 Maven 项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.FindBugs_all - DartifactId=FindBugs_all -DarchetypeArtifactId=maven- archetype-quickstart -Dversion=1.0-SNAPSHOT

    ```

1.  在 `pom.xml` 文件中，在`</project>`标签之前添加一个**构建**部分，内容如下：

    ```
    <build>
    <plugins>
    <plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>FindBugs-maven-plugin</artifactId>
    <version>3.0.0</version>
    <configuration>
    <FindBugsXmlOutput>true</FindBugsXmlOutput>
    <FindBugsXmlWithMessages>true</FindBugsXmlWithMessages>
    <onlyAnalyze>nl.berg.packt.FindBugs_all.candles.*</onlyAnal yze>
    <effort>Max</effort>
    </configuration>
    </plugin>
    </plugins>
    </build>
    ```

1.  创建目录 `src/main/java/nl/berg/packt/FindBugs_all/candles`。

1.  在 `candles` 目录中包括名为 `FindBugsCandle.java` 的文件，内容如下：

    ```
    package nl.berg.packt.FindBugs_all.candles;

    public class FindBugsCandle {
      public String answer="41";
      public boolean myBad(){
        String guess= new String("41");     if (guess==answer){ return true; }
        return false;
      }
    }
    ```

1.  创建一个名为 `ch5.quality.FindBugs` 的**Maven**项目。

1.  在**源代码管理**部分，选中**Subversion**单选框，添加到**Repository URL**中您的存储库 URL。

1.  在**构建**部分中添加 `clean compile findBugs:findBugs` 作为**目标和选项**。

1.  在**构建后操作**选项中，选择**发布 FindBugs 分析结果**。

1.  点击**保存**。

1.  运行作业。

1.  查看结果。

第一页是一个摘要页面，可以让您有效地放大细节，如下图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_10.jpg)

查看诸如**BAD_PRACTICE**之类的类别，可以查看触发的每种错误类型的描述：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_11.jpg)

您可以随后查看相关的代码。突出显示的代码有助于集中注意力，如下图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_12.jpg)

## 工作原理...

在这个示例中，您已经创建了一个标准的 Maven 项目，并添加了一个带有已知缺陷的 Java 文件。

`pom.xml` 配置强制 FindBugs 仅报告 `nl.berg.packt.FindBugs_all.candles` 包中类的缺陷。

在标准蜡烛中，`guess==answer` 这一行是一个典型的程序错误。两个对象的引用被比较，而不是它们字符串的值。由于 `guess` 对象是在上一行创建的，结果将始终为 `false`。这类缺陷可能会出现在程序中作为微妙的问题。JVM 缓存字符串，有时两个表面上不同的对象实际上是同一个对象。

## 更多内容...

FindBugs 在开发者中很受欢迎，并为多个流行的 IDE 提供插件。其结果通常作为其他工具的更广泛报告的一部分。

### FindBugs Eclipse 插件

Eclipse 插件的自动安装位置为 [`findbugs.cs.umd.edu/eclipse`](http://findbugs.cs.umd.edu/eclipse)。

默认情况下，FindBugs Eclipse 插件只启用了有限数量的规则。要增加测试集，您需要转到 **窗口** 下的 **首选项** 菜单选项，在左侧菜单中选择 **FindBugs**。在右侧，您将看到 **报告的 (可见的) 缺陷类别** 选项在 **报告者配置** 下。您现在可以调整可见的类别，如下图所示：

![FindBugs Eclipse 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_19.jpg)

### Xradar 和 Maven 仪表板

但是，对于生成的软件度量的累积，还有其他替代方案。Maven 仪表板就是一个例子 ([`mojo.codehaus.org/dashboard-maven-plugin/`](http://mojo.codehaus.org/dashboard-maven-plugin/))。您将需要将其连接到自己的数据库。在书籍 *Apache Maven 3 Cookbook, Srirangan, Packt Publishing* ([`www.packtpub.com/application-development/apache-maven-3-cookbook`](https://www.packtpub.com/application-development/apache-maven-3-cookbook)) 中的 第四章，*报告和文档* 中有一个名为 *设置 Maven 仪表板* 的配方。

Xradar 是仪表板的另一个例子 ([`xradar.sourceforge.net/usage/maven-plugin/howto.html`](http://xradar.sourceforge.net/usage/maven-plugin/howto.html))，而 QALab 是第三个 ([`qalab.sourceforge.net/multiproject/maven2-qalab-plugin/index.html`](http://qalab.sourceforge.net/multiproject/maven2-qalab-plugin/index.html))。

## 另请参阅

+   *启用额外的 FindBug 规则* 配方

+   *使用 FindBugs 查找安全缺陷* 配方

+   *激活更多 PMD 规则集* 配方

# 启用额外的 FindBug 规则

FindBugs 拥有广泛的辅助缺陷模式检测器。这些检测器被捆绑到一个贡献者项目中，托管在 SourceForge ([`sourceforge.net/projects/fb-contrib/`](http://sourceforge.net/projects/fb-contrib/))。

本配方详细介绍了如何从 `fb-contrib` 项目中添加额外的缺陷检测器到 FindBugs，并使用这些检测器捕获已知缺陷。

## 准备就绪

假设您已经按照之前的配方*使用 FindBugs 查找错误*。您将使用该配方的 Maven 项目作为起点。

### 提示

**fb-contrib 版本更改**

在以下配方中，Maven 会自动下载一个库文件（`.jar`）。构建可能会失败，因为开发人员已经增加了版本号。在这种情况下，要找到正确的文件名，请浏览[`downloads.sourceforge.net/project/fb-contrib/Current/`](http://downloads.sourceforge.net/project/fb-contrib/Current/)。

## 如何做...

1.  将顶层的`pom.xml`文件复制到`pom_fb.xml`。

1.  用以下内容替换`pom_fb.xml`的 FindBugs `<plugin>`部分：

    ```
    <plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>FindBugs-maven-plugin</artifactId>
    <version>3.0.0</version>
    <configuration>
    <FindBugsXmlOutput>false</FindBugsXmlOutput>
    <FindBugsXmlWithMessages>true</FindBugsXmlWithMessages>
    <onlyAnalyze>nl.berg.packt.FindBugs_all.candles.*</onlyAnal yze>
    <pluginList>http://downloads.sourceforge.net/project/fb- contrib/Current/fb-contrib-6.0.0.jar</pluginList>
    <effort>Max</effort>
    </configuration>
    </plugin>
    ```

1.  在`src/main/java/nl/berg/packt/fingbugs_all/candles`目录中，向`FindBugsFBCandle.java` Java 类添加以下代码片段：

    ```
    package nl.berg.packt.FindBugs_all.candles;

    public class FindBugsFBCandle {
      public String FBexample(){
        String answer="This is the answer";
        return answer;
      }
    }
    ```

1.  将更新提交到您的 Subversion 仓库。

1.  创建一个名为`ch5.quality.FindBugs.fb`的 Jenkins **Maven**作业。

1.  在**源代码管理**部分，选中**Subversion**单选框，并为**仓库 URL**添加代码的 URL。

1.  在**build**部分设置：

    +   **Root POM**设置为`pom_fb.xml`

    +   **目标和选项**设置为`clean compile Findbugs:Findbugs`

1.  在**构建设置**部分，检查**发布 FindBugs 分析结果**。

1.  点击**保存**。

1.  运行作业。

1.  当作业构建完成后，查看**FindBugs 警告**链接。您现在将看到一个新的警告**USBR_UNNECESSARY_STORE_BEFORE_RETURN**。

## 它是如何工作的...

要包含外部检测器，您添加了一行额外的内容到 FindBugs Maven 配置中，如下所示：

```
<pluginList>http://downloads.sourceforge.net/project/fb- contrib/Current/fb-contrib-6.0.0.jar</pluginList>
```

值得访问 SourceForge 检查检测器的最新版本。

目前，使用 Maven 的依赖管理无法从存储库中拉取检测器，尽管这可能会改变。

在这个配方中，您已经添加了一个 Java 类来触发新的错误检测规则。反模式是在返回之前创建答案对象的不必要行。匿名返回对象更加简洁，例如：

```
return "This is the answer";
```

反模式触发了**USBR_UNNECESSARY_STORE_BEFORE_RETURN**模式，该模式在`fb-contrib`项目的主页上有描述。

## 还有更多...

Java 语言有许多难以理解的微妙边界情况，直到通过真实示例解释。捕捉知识的一种极好方式是在您的代码中遇到问题时自己编写示例。注入标准蜡烛是测试团队知识的一种自然方式，并在 QA 过程中进行目标练习。

FindBugs 项目根据 Joshua Bloch 和 Neal Gafter 的书《Java Puzzlers》（[`www.javapuzzlers.com/`](http://www.javapuzzlers.com/)）的内容生成了一些他们的检测器。

## 另请参阅

+   *使用 FindBugs 查找错误*配方

+   *使用 FindBugs 查找安全缺陷*配方

+   *激活更多 PMD 规则集*配方

# 使用 FindBugs 查找安全缺陷

在本示例中，你将使用 FindBugs 发现 Java 服务器页面中的安全漏洞以及有缺陷的 Java 类中的一些安全缺陷。

## 准备工作

要么按照第三章 *构建软件* 中的 *基于 JSP 语法错误失败的 Jenkins 任务* 配方，要么使用 Packt Publishing 网站提供的项目下载。

## 如何操作...

1.  在 `<build>` 下的 `<plugins>` 中编辑 `pom.xml` 文件，添加 FindBugs 插件并添加以下内容：

    ```
    <plugins>
    <plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>findBugs-maven-plugin</artifactId>
    <version>3.0.0</version>
    <configuration>
    <FindBugsXmlOutput>true</FindBugsXmlOutput>
    <FindBugsXmlWithMessages>true</FindBugsXmlWithMessages>
    <effort>Max</effort>
    </configuration>
    </plugin>
    ```

1.  创建目录结构 `src/main/java/nl/berg/packt/finbugs_all/candles`。

1.  添加 Java 文件 `FindBugsSecurity.java`，内容如下：

    ```
    package nl.berg.packt.FindBugs_all.candles;

    public class FindBugsSecurityCandle {
      private final String[] permissions={"Read", "SEARCH"};
      private void infiniteLoop(int loops){
        infiniteLoop(99);
      }

      public String[] exposure(){
        return permissions;
      }
      public static void main(String[] args) { 
        String[] myPermissions = new FindBugsSecurityCandle().exposure();
        myPermissions[0]="READ/WRITE";
        System.out.println(myPermissions[0]);
      }
    }
    ```

1.  将更新提交到你的 Subversion 仓库。

1.  创建一个名为 `ch5.quality.FindBugs.security` 的 **Maven** Jenkins 任务。

1.  在 **源代码管理** 部分，选中 **Subversion** 单选框，并在 **Repository URL** 文本框中添加你的 Subversion 仓库位置**。**

1.  在 **目标和选项** 的 **build** 部分下，将值设置为 `clean package findBugs:findBugs`。

1.  在 **构建设置** 部分，选中 **发布 FindBugs 分析结果**。

1.  点击 **保存**。

1.  运行该任务。

1.  当任务完成后，查看 **FindBugs Warning** 链接。注意，JSP 包存在一个关于 **XSS_REQUEST_PARAMETER_TO_JSP_WRITER** 的警告。然而，该链接无法找到源代码的位置。

1.  将 `src/main/webapp/index.jsp` 复制到 `jsp/jsp.index_jsp`。

1.  提交到你的 Subversion 仓库。

1.  再次运行任务。

1.  在 **FindBugs Warning** 链接下查看结果。你现在可以查看 JSP 源代码了。

## 工作原理...

JSP 首先从文本转换为 Java 源代码，然后编译。FindBugs 通过解析编译后的 Java 字节码来工作。

原始的 JSP 项目存在严重的安全漏洞。它信任来自互联网的输入。这导致了许多攻击向量，包括 XSS 攻击 ([`en.wikipedia.org/wiki/Cross-site_scripting`](http://en.wikipedia.org/wiki/Cross-site_scripting))。使用允许标记的白名单来解析输入是减少风险的一种方法。FindBugs 发现了这个缺陷并以 `XSS_REQUEST_PARAMETER_TO_JSP_WRITER` 进行警告。Jenkins FindBugs 插件详细说明了错误类型，因为你在配置中打开了消息：

```
<FindBugsXmlWithMessages>true</FindBugsXmlWithMessages>
```

FindBugs 插件尚未实现对 JSP 文件位置的理解。当单击链接到源代码时，插件会在错误的位置查找。一个临时解决方案是将 JSP 文件复制到 Jenkins 插件期望的位置。

FindBugs 报告的行号位置也毫无意义。它指向了生成自 `.jsp` 文件的 `.java` 文件中的行，而不是直接指向 JSP 文件。尽管存在这些限制，FindBugs 仍然能够发现有关 JSP 缺陷的有用信息。

### 注意

JSP Bug 检测的替代方案是 PMD。你可以从命令行配置它仅扫描 JSP 文件，使用选项 `–jsp`，参见：[`pmd.sourceforge.net/jspsupport.html`](http://pmd.sourceforge.net/jspsupport.html)

## 还有更多...

虽然 FindBugs 有一些属于安全类别的规则，但还有其他发现安全相关缺陷的 bug 检测器。标准烛台类包括两种此类缺陷。第一个是一个递归循环，将不断从其内部调用相同的方法，如下面的代码所示：

```
private void infiniteLoop(int loops){
  infiniteLoop(99);
}
```

也许程序员打算使用计数器来在 99 个循环后强制退出，但是并不存在执行此操作的代码。如果调用此方法，最终结果是它将不断调用自身，直到堆栈保留的内存被消耗完并且应用程序失败。这也是一个安全问题；如果攻击者知道如何到达此代码，他们可以通过**拒绝服务**（**DOS**）攻击使相关应用程序崩溃。

标准烛台中捕获的另一个攻击是能够更改看起来不可变的数组中的内容。确实，数组的引用不能更改，但是数组元素的内部引用可以。在示例中，一个有动机的黑客可以访问内部对象，并将 READ 权限更改为 READ/WRITE 权限。为了防止这种情况发生，考虑制作原始数组的防御性副本，并将副本传递给调用方法。

### 注意

OWASP 项目提供了大量关于测试安全性的信息，请查看以下链接：

[`www.owasp.org/index.php/Category:OWASP_Java_Project`](https://www.owasp.org/index.php/Category:OWASP_Java_Project)

## 另请参阅

+   *使用 FindBugs 查找 bug 的方法*

+   *启用额外的 FindBug 规则* 配方

+   *激活更多 PMD 规则集* 配方

+   第三章 中的 *为集成测试配置 Jetty* 配方，*构建软件*

# 验证 HTML 的有效性

该配方告诉你如何使用 Jenkins 对 HTML 页面进行验证，以符合 HTML 和 CSS 标准。

Web 浏览器并不挑剔。您可以在应用程序中拥有损坏的模板，生成的 HTML 在一个浏览器上可以正常工作，但在另一个浏览器上却很难看。验证可以提高一致性，并及早发现非平凡但难以发现的问题。

您可以上传并验证您的 HTML 文件是否符合 W3C 的统一验证器 ([`code.w3.org/unicorn`](http://code.w3.org/unicorn))。统一验证器将根据多个聚合服务检查您的网页的正确性。Jenkins 插件会自动为您执行此操作。

## 准备工作

安装 Unicon 验证插件（[`wiki.jenkins-ci.org/display/JENKINS/Unicorn+Validation+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Unicorn+Validation+Plugin)）。如果还没有安装，请同时安装 Plot 插件（[`wiki.jenkins-ci.org/display/JENKINS/Plot+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Plot+Plugin)）。

## 如何操作...

1.  创建一个名为 `ch5.quality.html` 的自由风格作业。

1.  在 **构建** 部分内，**添加构建步骤**，选择 **Unicorn 验证器**。

1.  对于要验证的站点 **Site to validate** 输入，请添加允许测试的站点的 URL。

1.  单击 **保存**。

1.  运行作业。

1.  查看 **工作区**，单击 `unicorn_output.html` 链接，然后单击 `markup-validator_errors.properties`。对于属性文件的内容，您将看到类似 `YVALUE=2` 的内容。

1.  **配置** 项目。在 **后构建操作** 部分，勾选 **绘制构建数据**，添加以下细节：

    +   **绘图组**：验证错误

    +   **绘图标题**：标记验证错误

    +   **要包含的构建数**：40

    +   **绘图 y 轴标签**：错误

    +   **绘图样式**：区域

    +   **数据系列文件**：`markup-validator_errors.properties`

    +   验证 **从属性文件加载数据** 单选框是否被选中

    +   **数据系列图例标签**：反馈错误

1.  单击 **保存**。

1.  运行作业。

1.  查看 **绘图** 链接。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_20.jpg)

## 工作原理...

Unicon 验证插件使用 W3C 的验证服务生成配置的 URL 的报告。插件处理返回的报告并获取缺陷的绝对计数。然后，总计值被放置在属性文件中，然后绘图插件会获取这些值（请参阅 第三章 中的 *在 Jenkins 中绘制替代代码度量* 配方，*构建软件*）。如果看到警告突然激增，请查看 HTML 页面以查找重复缺陷。

## 还有更多...

从单元测试中获得良好的代码覆盖率相当困难。这在项目较大且有多个团队采用不同实践的情况下尤为明显。通过使用尽可能访问应用程序中尽可能多的链接的工具，可以显著提高对 Web 应用程序的自动化测试覆盖率。这包括 HTML 验证器、链接检查器、搜索引擎爬虫和安全工具。考虑在集成测试期间设置一系列工具来访问您的应用程序，并记住解析日志文件以查找意外错误。您可以使用 第一章 中的 *通过日志解析故意失败的构建* 配方自动化日志解析，*维护 Jenkins*。

### 注意

有关逐步验证在线内容的详细信息，请访问 [`www.w3.org/QA/2002/09/Step-by-step`](http://www.w3.org/QA/2002/09/Step-by-step)。

# 使用 JavaNCSS 进行报告

JavaNCSS ([`javancss.codehaus.org/`](http://javancss.codehaus.org/)) 是一个软件度量工具，它计算两种类型的信息：第一种是包中活动的、注释的或与 JavaDoc 相关的源代码行数的总数。第二种类型基于存在多少不同的决策分支来计算代码的复杂性。

Jenkins JavaNCSS 插件忽略了复杂性计算，而是专注于更容易理解的行数统计。

### 注意

**NCSS** 代表**非注释源语句**，即代码行数减去注释和额外的换行符。

## 准备就绪

安装 JavaNCSS 插件 ([`wiki.jenkins-ci.org/display/JENKINS/JavaNCSS+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/JavaNCSS+Plugin))。

## 如何做...

1.  创建一个名为 `ch5.quality.ncss` 的**Maven**项目。

1.  在**源代码管理**部分，选择**Subversion**单选框。

1.  添加**仓库 URL** [`source.sakaiproject.org/contrib/learninglog/tags/1.0`](https://source.sakaiproject.org/contrib/learninglog/tags/1.0)。

1.  查看**构建触发器**，确保没有激活。

1.  在**构建**部分的**目标和选项**下，键入`clean javancss:report`。

1.  在**构建设置**部分，勾选**发布 Java NCSS 报告**。

1.  点击**保存**。

1.  运行该作业。

1.  查看**Java NCSS 报告**链接。

1.  查看工作区中的顶级 `pom.xml` 文件，例如，`http://localhost:8080job/ch5.quality.ncss/ws/pom.xml`。![怎么做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_21.jpg)

## 工作原理...

该作业从 Sakai 项目的学习日志工具子版本库中提取了源代码。该项目是一个多模块项目，API 与实现分离。

JavaNCSS 不需要编译的类或对 Maven `pom.xml` 文件的修改；这使得循环简单。该作业运行了一个 Maven 目标，通过 JavaNCSS Jenkins 插件发布了报告。

回顾报告，实现相对于其他包具有更多的活动代码行数。API 的文档对其他开发人员重用代码至关重要。值得注意的是，API 中没有 JavaDoc 行。

摘要表中的缩写具有以下含义：

+   **类**：这是包中类的数量。

+   **函数**：这是包中函数的数量。

+   **JavaDocs**：这是包中不同 JavaDoc 块的数量。这并不完全准确，因为大多数现代 IDE 使用样板模板生成类。因此，您可能会生成大量质量低劣的 JavaDoc，从而产生误导性结果。

+   **NCSS**：这是源代码中非注释行的数量。

+   **JLC**：这是 JavaDoc 的行数。

+   **SLCLC**：这是仅包含单个注释的行数。

+   **MLCLC**：这是多行注释中包含的源代码行数。

构建摘要显示了当前任务与上一任务之间的变更（增量）信息，例如：

```
    classes (+28)
    functions (+349)
    ncss (+2404)
    javadocs (+22)
    javadoc lines (+80)
    single line comments (+63)
    multi-line comments (+215)
```

`+` 符号表示代码已添加，`-` 表示已删除。如果你看到大量代码涌入，但 JavaDoc 的涌入量低于平常，那么要么代码是自动生成的，要么更可能是为了赶上市场而匆忙开发。

## 这还不是全部...

当你已经习惯于相对简单的 JavaNCSS 摘要的含义后，考虑将 JDepend 添加到您的代码度量安全网中。JDepend 生成了更广泛的与质量相关的指标（[`clarkware.com/software/JDepend.html`](http://clarkware.com/software/JDepend.html)，[`mojo.codehaus.org/jdepend-maven-plugin/plugin-info.html`](http://mojo.codehaus.org/jdepend-maven-plugin/plugin-info.html)，以及 [`wiki.jenkins-ci.org/display/JENKINS/JDepend+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/JDepend+Plugin)）。

JDepend 生成的最重要的指标之一是**循环依赖**。如果类 A 依赖于类 B，而类 B 又依赖于类 A，那么这就是一个循环依赖。当存在这样的依赖关系时，表明存在某种事情可能出错的风险，例如资源竞争、无限循环或同步问题。可能需要重构以消除责任不清晰性。

# 使用外部 pom.xml 文件检查代码样式

如果你只想检查代码的文档质量而不更改其源代码，则注入自己的 `pom.xml` 文件。这个配方向你展示了如何为 Checkstyle 进行此操作。Checkstyle 是一个工具，根据明确定义的标准（例如 Sun 编码规范）检查大多数文档。

## 准备就绪

安装 Checkstyle 插件（[`wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin)）。

### 小贴士

如果您因为 **AbstractMapBasedMultimap** 上的 **illegalAccessError** 错误而遇到问题，那么这可能是由于 **Jenkins-22252** 报告的错误所致（[`issues.jenkins-ci.org/browse/JENKINS-22252`](https://issues.jenkins-ci.org/browse/JENKINS-22252)）。当前解决方案是使用 Maven 的版本 3.0.5 运行。

## 如何执行...

1.  创建名为 `/var/lib/jenkins/OVERRIDE` 的目录。

1.  确保目录的所有者是 Jenkins 用户和组 `sudo chown jenkins:jenkins /var/lib/jenkins/OVERRIDE`。

1.  创建文件 `/var/lib/Jenkins/OVERRIDE/pom_checkstyle.xml`，内容如下：

    ```
    <project  
      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
      <modelVersion>4.0.0</modelVersion>
      <groupId>nl.berg.packt.checkstyle</groupId>
      <artifactId>checkstyle</artifactId>
      <packaging>pom</packaging>
      <version>1.0-SNAPSHOT</version>
      <name>checkstyle</name>
      <url>http://maven.apache.org</url>

    <modules>
    <module>api</module>
    <module>help</module>
    <module>impl</module>
    <module>util</module>
    <module>pack</module>
    <module>tool</module>
    <module>assembly</module>
    <module>deploy</module>
    <module>bundle</module>
    </modules>
    <build>
    <plugins>
          <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-checkstyle-plugin</artifactId>
            <version>2.8</version>
          </plugin>
        </plugins>
    </build>
    <properties>
    <project.build.sourceEncoding>UTF-8
    </project.build.sourceEncoding>
    </properties>
    </project>
    ```

1.  确保文件的所有者是 Jenkins 用户和组 `sudo chown jenkins:jenkins /var/lib/jenkins/OVERRIDE/pom_checkstyle.xml`。

1.  创建一个名为 `ch5.quality.checkstyle.override` 的 **Maven** 任务。

1.  在 **源码管理** 部分，选中 **Subversion** 并添加 Subversion 存储库 [`source.sakaiproject.org/svn/profile2/tags/profile2-1.4.5`](https://source.sakaiproject.org/svn/profile2/tags/profile2-1.4.5)。

1.  在**添加预构建**步骤的**预步骤**部分中，选择**执行 shell**。

1.  在命令文本区域中添加 `cp /var/lib/Jenkins/OVERRIDE/pom_checkstyle.xml`。

1.  在**build**部分下添加：

    +   **根 POM**：`pom_checkstyle.xml`

    +   **目标和选项**：`clean checkstyle:checkstyle`

1.  在**构建设置**部分，勾选**发布 Checkstyle 分析结果**。

1.  单击**保存**。

1.  运行作业多次，查看输出。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_13.jpg)

## 工作原理...

**profile2** 工具在全球范围内由数百万用户在 Sakai 学习管理系统([`sakaiproject.org`](http://sakaiproject.org))中使用。这是一个真实的工业级编码。它是一个社交中心，用于管理其他人可以看到你帐户详细信息的内容。该项目将代码分为实现、API 和模型。

在这个案例中，您创建了一个替换的`pom.xml`文件。您不需要复制原始`pom.xml`中的任何依赖项，因为 Checkstyle 不需要编译代码来进行计算。

然后作业将`pom_checkstyle.xml`文件复制到主工作区。`pom_checkstyle.xml`文件中未详细配置 Checkstyle，因为我们只对总体趋势感兴趣。但是，如果您想要放大细节，可以配置 Checkstyle 以基于特定指标生成结果，例如布尔表达式的复杂性或非注释源语句（NCSS）[`checkstyle.sourceforge.net/config_metrics.html`](http://checkstyle.sourceforge.net/config_metrics.html)。

## 还有更多...

您可以使用 Jenkins XML API 远程查看大多数质量测量工具的统计信息。Checkstyle、PMD、FindBugs 等的语法是：

```
Jenkins_HOST/job/[Job-Name]/[Build-Number]/[Plugin-URL]Result/api/xml

```

例如，在这个案例中，类似下面的 URL 将起作用：

```
localhost:8080/job/ch5.quality.checkstyle.override/11/checkstyleResult/api/xml

```

此食谱的返回结果类似于以下内容：

```
<checkStyleReporterResult>
<newSuccessfulHighScore>true</newSuccessfulHighScore>
<warningsDelta>38234</warningsDelta>
<zeroWarningsHighScore>1026944</zeroWarningsHighScore>
<zeroWarningsSinceBuild>0</zeroWarningsSinceBuild>
<zeroWarningsSinceDate>0</zeroWarningsSinceDate>
</checkStyleReporterResult>
```

要远程获取数据，您需要进行身份验证。有关如何执行远程身份验证的信息，请参阅第三章中的*通过 Jenkins API 远程触发作业*食谱，*构建软件*。

## 另请参阅

+   *伪造 Checkstyle 结果* 食谱

# 伪造 Checkstyle 结果

本食谱详细介绍了如何伪造 Checkstyle 报告。 这将允许您将自定义数据挂接到 Checkstyle Jenkins 插件（[`wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin)），公开您的自定义测试结果而无需编写新的 Jenkins 插件。 与在第三章 *构建软件*中使用*在 Jenkins 中绘制替代代码指标*的食谱相比，它显示结果的位置。 您可以使用 Analysis Collector 插件（[`wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Analysis+Collector+Plugin)）将虚假结果与其他指标摘要汇总。

## 准备工作

如果尚未安装 Checkstyle，请安装并在您的 Subversion 存储库中为代码创建一个新目录。

## 如何做...

1.  创建一个名为`generate_data.pl`的 Perl 脚本文件，内容如下：

    ```
    #!/usr/bin/perl
    $rand=int(rand(9)+1);

    print <<MYXML;
    <?xml version="1.0" encoding="UTF-8"?>
    <checkstyle version="5.4">
    <file name="src/main/java/MAIN.java">
        <error line="$rand" column="1" severity="error"  message="line=$rand" source="MyCheck"/>
    </file>
    </checkstyle>
    MYXML
    #Need this extra line for the print statement to work
    ```

1.  创建目录`src/main/java.`

1.  添加 Java 文件`src/main/java/MAIN.java`，内容如下：

    ```
    //line 1
    public class MAIN {
    //line 3
    public static void main(String[] args) {
      System.out.println("Hello World"); //line 5
    }
    //line 7
    }
    //line 9
    ```

1.  将文件提交到您的 Subversion 存储库。

1.  创建一个 Jenkins 自由风格作业`ch5.quality.checkstyle.generation`。

1.  在**源代码管理**部分，选中**Subversion**并添加**存储库 URL**：您的存储库 URL。

1.  在**构建**部分，选择**构建步骤**为**执行 Shell**。 在命令输入中添加命令`perl generate_data.pl > my-results.xml`。

1.  在**后构建操作**部分，选中**发布 Checkstyle 分析结果**。 在**Checkstyle 结果**文本输入中，添加`my-results.xml`。

1.  点击**保存**。

1.  运行作业多次，审查结果和趋势。

顶层报告提到了您的新规则：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_22.jpg)

点击代码链接**MAIN.java**会带您到代码页面，并随机选择由 Perl 代码突出显示的错误行，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_23.jpg)

## 它是如何工作的...

本章中使用的插件将其信息存储在 XML 文件中。 Checkstyle XML 结构是所有工具中最简单的，因此是我们生成的虚假结果所选择的 XML 格式。

Perl 代码创建一个简单的 XML 结果文件，选择 1...9 之间的一行失败。 输出格式与以下代码类似：

```
<checkstyle version="5.4">
<file name="src/main/java/MAIN.java">
    <error line="9" column="1" severity="error" message="line=9" source="MyCheck"/>
</file>
```

文件位置是相对于 Jenkins 工作空间的。 Jenkins 插件打开此位置找到的文件，以便它可以将其显示为源代码。

对于找到的每个错误，创建一个`<error>`标签。 该插件将严重级别`错误`映射到`高`。

## 还有更多...

您可能不必将结果强制转换为虚假格式。首先考虑使用 xUnit 插件 ([`wiki.jenkins-ci.org/display/JENKINS/xUnit+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/xUnit+Plugin))。这是一个实用插件，支持从不同的回归测试框架转换结果。该插件将不同的结果类型转换为标准化的 JUnit 格式。您可以在以下位置找到 JUnit 结果模式：[`windyroad.org/dl/Open%20Source/JUnit.xsd`](http://windyroad.org/dl/Open%20Source/JUnit.xsd)。

## 另请参阅

+   *使用外部 pom.xml 检查样式* 配方

# 将 Jenkins 与 SonarQube 集成

SonarQube，以前称为 Sonar，是一个快速发展的应用程序，用于报告质量指标和查找代码热点。本篇详细介绍了如何通过 Jenkins 插件生成代码指标，然后直接将其推送到 Sonar 数据库。

## 准备工作

安装 Sonar 插件 ([`docs.codehaus.org/display/SONAR/Jenkins+Plugin`](http://docs.codehaus.org/display/SONAR/Jenkins+Plugin))。

下载并解压 SonarQube。您可以直接从 bin 目录中运行它，选择其中的 OS 目录。例如，Desktop Ubuntu 的启动脚本是 `bin/linux-x86-32/sonar.sh console`。现在您有一个不安全的默认实例运行在端口 `9000` 上。要获取更完整的安装说明，请查看：

[`docs.codehaus.org/display/SONAR/Setup+and+Upgrade`](http://docs.codehaus.org/display/SONAR/Setup+and+Upgrade) 和 [`docs.sonarqube.org/display/SONAR/Installing`](http://docs.sonarqube.org/display/SONAR/Installing)

## 如何做...

1.  在主要的 Jenkins 配置 (`/configure`) 中，在 **Sonar** 部分为 **Name** 添加 `localhost`。

1.  点击 **保存**。

1.  创建一个名为 `ch5.quality.sonar` 的 **Maven** 作业。

1.  在 **源代码管理** 部分的 **Repository URL** 下添加 [`source.sakaiproject.org/svn/announcement/tags/announcement-2.9.3`](https://source.sakaiproject.org/svn/announcement/tags/announcement-2.9.3)。

1.  在 **构建触发器** 部分，验证未选择任何构建触发器。

1.  在 **构建** 部分的 **Goals and options** 下添加 `clean install`。

1.  对于 **后构建操作** 部分，勾选 **Sonar**。

1.  点击 **保存**。

1.  运行该作业。

1.  点击 **Sonar** 链接并查看新生成的报告。

报告的顶层提供了关键质量指标的快速摘要，如下图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_14.jpg)

从左侧菜单中，您可以深入了解详细信息：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_15.jpg)

## 它的工作原理...

源代码是 Sakai 中使用的公告工具。该项目是一个带有一些相对复杂细节的多模块项目。

默认的 SonarQube 实例预配置了内存数据库。Jenkins 插件已经知道默认配置，并且需要很少的额外配置。Jenkins Sonar 插件不需要你重新配置 `pom.xml`。Jenkins 插件处理生成结果的所有细节。

该作业首先运行 Maven 清理工具来清除工作空间中的旧编译代码，然后运行 `install` 目标，将代码编译为其一个阶段的一部分。

Jenkins Sonar 插件然后直接与 Sonar 数据库联系，并添加先前生成的结果。现在你可以在 Sonar 应用程序中看到结果了。

## 还有更多……

Sonar 是一个专门用于测量软件质量指标的应用程序。像 Jenkins 一样，它拥有一个专门的、活跃的社区。你可以期待一个积极进取的改进路线图。例如，它具有指出可疑代码热点的能力、视觉上吸引人的报告仪表板、易于配置和详细控制检查规则以查看等功能，目前都使它与 Jenkins 有所区别。

### SonarQube 插件

通过添加额外的插件很容易扩展 Sonar 的功能。你可以在以下 URL 中找到官方提到的插件集：

[`docs.codehaus.org/display/SONAR/Plugin+Library`](http://docs.codehaus.org/display/SONAR/Plugin+Library)

这些插件包括一些与 Jenkins 中找到的功能相当的功能。Sonar 明显不同的地方在于治理插件，代码覆盖率成为捍卫项目质量的核心。

### 备选的聚合器 - 违规插件

Jenkins 违规插件接受来自一系列质量度量工具的结果，并将它们合并成一个统一的报告。这个插件是 Jenkins 中最接近 Sonar 的功能。在决定是否需要在基础架构中添加额外应用程序之前，值得对其进行审查，以查看它是否满足你的质量度量需求。

## 另请参阅

+   *通过代码覆盖率寻找“有味道”的代码* 配方

+   *激活更多的 PMD 规则集* 配方

+   *使用 JavaNCSS 进行报告* 配方

# 使用 R 插件分析项目数据

这个配方描述了如何使用 R 来处理项目工作空间中每个文件的度量标准。该配方通过遍历工作空间并收集特定扩展名（如 Java）的文件列表来实现此目的。然后，R 脚本分析每个文件，最终将结果以图形格式绘制到 PDF 文件中。这种工作流程几乎适用于所有与软件项目质量相关的分析。该配方很容易定制，以适应更复杂的任务。

在这个例子中，我们正在查看文本文件的字数大小，将大文件的名称打印到控制台，并绘制所有文件的大小。通过可视化表示，你可以很容易地看出哪些文件特别大。如果你的属性文件比其他属性文件大得多，那么它可能是损坏的。如果 Java 文件太大，那么它就难以阅读和理解。

## 准备工作

假设你已经按照第四章中*Simplifying powerful visualizations using the R plugin*一节的方法，并且已经安装了 R 插件([`wiki.jenkins-ci.org/display/JENKINS/R+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/R+Plugin))。

## 操作步骤...

1.  创建一个名为`ch5.R.project.data`的自由样式作业。

1.  在**源代码管理**部分，选择**Subversion**。

1.  添加**仓库 URL**为[`source.sakaiproject.org/svn/profile2/trunk`](https://source.sakaiproject.org/svn/profile2/trunk)。

1.  在**构建**部分，选择**添加构建步骤**，然后选择**执行 R 脚本**。

1.  在**脚本文本**区域添加以下代码：

    ```
    processFile <- function(file){
      text <- readLines(file,encoding="UTF-8")
      if (length(text)> 500) print(file)
      length(text)
    }
    javaFiles <- list.files(Sys.getenv('WORKSPACE'), recursive = TRUE, full.names = TRUE, pattern = "\\.java$")
    propertiesFiles <- list.files(Sys.getenv('WORKSPACE'), recursive = TRUE, full.names = TRUE, pattern = "\\.properties$")
    resultJava <- sapply(javaFiles, processFile)
    resultProperties <- sapply(propertiesFiles,processFile)
    warnings()
    filename <-paste('Lengths_JAVA_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep ="")
    pdf(file=filename)
    hist(resultJava,main="Frequency of length of JAVA files")

    filename <-paste('Lengths_Properties_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
    pdf(file=filename)
    hist(resultProperties,main="Frequency of length of Property files")
    ```

1.  点击**保存**按钮。

1.  点击**立即构建**图标。

1.  查看构建的控制台输出。它应该类似于以下内容：

    ```
    At revision 313948
    no change for https://source.sakaiproject.org/svn/profile2/trunk since the previous build
    [ch5.R.project.data] $ Rscript /tmp/hudson7641363251840585368.R
    [1] "/var/lib/jenkins/workspace/ch5.project.data/api/src/java/org/sakaiproject/profile2/logic/SakaiProxy.java"
    [1] "/var/lib/jenkins/workspace/ch5.project.data/impl/src/java/org/sakaiproject/profile2/conversion/ProfileConverter.java"
    [1] "/var/lib/jenkins/workspace/ch5.project.data/impl/src/java/org/sakaiproject/profile2/dao/impl/ProfileDaoImpl.java"
    14: In readLines(file, encoding = "UTF-8") :
      incomplete final line found on '/var/lib/jenkins/workspace/ch5.project.data/tool/src/java/org/apache/wicket/markup/html/form/upload/MultiFileUploadField_ca_ES.properties'
    Finished: SUCCESS
    ```

1.  访问工作空间，查看文件`Lengths_Properties_1.pdf`，`Lengths_JAVA_1.pdf`。![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_16.jpg)

注意具有大量行的落单文件。属性文件的长度应该大致相同，因为它们包含了 GUI 的国际翻译。

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_05_17.jpg)

这感觉像是一个平衡良好的项目，因为只有少数文件有大量的代码行。

## 工作原理...

你从子版本加载了[profile2 工具](https://source.sakaiproject.org/svn/profile2/trunk)。这个代码被全球数百万学生使用，代表了成熟、现实的生产代码。

在你的 R 脚本中，你定义了一个函数，它以文件名作为输入，然后将文件读入文本对象。然后函数检查行数是否大于 500。如果行数大于 500，则文件名会打印到控制台输出。最后，函数返回文本文件的行数。

```
processFile <- function(file){
  text <- readLines(file,encoding="UTF-8")
  if (length(text)> 500) print(file)
  length(text)
}
```

接下来，脚本会在工作空间下查找属性和 Java 文件。文件搜索由`pattern`参数定义的值进行过滤。在这种情况下，`.java`：

```
javaFiles <- list.files(Sys.getenv('WORKSPACE'), recursive = TRUE, full.names = TRUE, pattern = "\\.java$")
propertiesFiles <- list.files(Sys.getenv('WORKSPACE'), recursive = TRUE, full.names = TRUE, pattern = "\\.properties$")
```

文件名列表逐个传递给之前定义的`processFile`函数。结果是一系列文件长度，存储在`resultJava`和`resultProperties`对象中：

```
resultJava <- sapply(javaFiles, processFile)
resultProperties <- sapply(propertiesFiles,processFile)
```

`warnings()`函数生成了在运行`sapply`命令时生成的问题列表：

```
14: In readLines(file, encoding = "UTF-8") :
  incomplete final line found on '/var/lib/jenkins/workspace/ch5.project.data/tool/src/java/org/apache/wicket/markup/html/form/upload/MultiFileUploadField_ca_ES.properties'
```

这表明期望文件末尾有一个新行。这不是一个关键问题。显示警告是发现损坏文件的有益方法。

最后，我们生成了两个结果的直方图，一个用于 Java 文件，另一个用于属性文件。文件名由一个常量字符串和一个唯一设置为每次构建的`BUILD_NUMBER`环境变量组成。`pdf`函数告诉 R 输出要存储在 PDF 文件中，而`hist`函数则绘制结果的直方图：

```
filename <-paste('Lengths_JAVA_',Sys.getenv('BUILD_NUMBER'),'.pdf',sep="")
pdf(file=filename)
hist(resultJava,main="Frequency of length of JAVA files")
```

## 还有更多...

当编写用于处理文件的 R 代码时，不要重复造轮子。R 有许多用于操作文本的库。`stringi`库就是一个例子（[`cran.r-project.org/web/packages/stringi/stringi.pdf`](http://cran.r-project.org/web/packages/stringi/stringi.pdf)）。这是一些计算文本文件中单词数量的示例代码：

```
library(stringi)
processFile <-function(file){
stri_stats_latex(readLines(file,encoding="UTF-8"))
}
results<-processFile(file.choose())
paste("Number of words in file:", results[4])
```

脚本定义了函数`processFile`。该函数需要一个文件名。文件被读入`stri_stats_latex`函数中。这个函数包含在`stringi`库中。它以矢量（一系列数字）的形式返回文件的摘要。

`file.choose()`函数弹出一个对话框，允许您浏览文件系统并选择文件。调用返回文件的完全限定路径。它将值传递给`processFile`函数调用。结果存储在结果矢量中。然后脚本打印出第四个数字，即文件中的单词数。

### 注

另一个用于文本挖掘的有趣的 R 包是`tm`：([`cran.r-project.org/web/packages/tm/tm.pdf`](http://cran.r-project.org/web/packages/tm/tm.pdf))。`tm`包具有加载一组文本文件并以多种不同方式分析它们的能力。

## 另请参阅

+   *利用 R 插件简化强大的可视化* 在 第四章 中的配方，*通过 Jenkins 进行通信*

+   *通过日志解析添加一个警告存储使用违规的作业* 在 第一章 中的配方，*维护 Jenkins*


# 第六章：远程测试

在本章中，我们将涵盖以下配方：

+   从 Jenkins 部署 WAR 文件到 Tomcat

+   创建多个 Jenkins 节点

+   为从节点定制设置脚本

+   使用 FitNesse 进行测试

+   激活 FitNesse HtmlUnit 夹具

+   运行 Selenium IDE 测试

+   使用 Selenium WebDriver 触发 failsafe 集成测试

+   创建 JMeter 测试计划

+   报告 JMeter 性能指标

+   使用 JMeter 断言进行功能测试

+   启用 Sakai Web 服务

+   使用 SoapUI 编写测试计划

+   报告 SoapUI 测试结果

# 介绍

本章结束时，您将对 Web 应用程序和 Web 服务运行性能和功能测试。其中包括两个典型的设置配方：第一个是通过 Jenkins 将 WAR 文件部署到应用服务器，第二个是创建多个从节点，准备将测试工作从主节点移开。

通过 Jenkins 进行远程测试会显著增加基础设施中的依赖关系，从而增加了维护工作量。远程测试是一个特定于域的问题，减少了可以编写测试的受众规模。

本章强调了使测试编写对大众可及的必要性。接纳尽可能多的受众可以提高测试捍卫应用程序意图的机会。

突出显示的技术包括：

+   **FitNesse**：这是一个 wiki，您可以在其中编写不同类型的测试。使用 wiki 类似的语言来实时表达和更改测试，为功能管理员、顾问和最终用户提供了一个表达其需求的地方。您将学会如何通过 Jenkins 运行 FitNesse 测试。FitNesse 还是一个框架，您可以扩展 Java 接口以创建新的测试类型。这些测试类型称为夹具；有许多可用的夹具，包括用于数据库测试、从命令行运行工具以及对 Web 应用程序进行功能测试的夹具。

+   **JMeter**：这是一个流行的开源工具，用于压力测试。它还可以通过使用断言进行功能测试。JMeter 有一个允许您构建测试计划的 GUI。然后将测试计划存储在 XML 格式中。可以通过 Maven 或 Ant 脚本执行 JMeter。JMeter 非常高效，通常一个实例就足以对基础设施造成很大压力。但是，对于超高负载场景，JMeter 可以触发一系列 JMeter 实例。

+   **Selenium**：这是功能测试 Web 应用程序的事实工业标准。使用 Selenium IDE，您可以在 Firefox 或 Chrome 中记录您的操作，以 HTML 格式保存以供以后重播。测试可以通过 Maven 使用 Selenium RC（远程控制）重新运行。通常会使用具有不同操作系统和浏览器类型的 Jenkins 从节点来运行测试。另一种选择是使用 Selenium Grid（[`code.google.com/p/selenium/wiki/Grid2`](https://code.google.com/p/selenium/wiki/Grid2)）。

+   **Selenium 和 TestNG 单元测试**：编写单元测试使用 TestNG 框架进行功能测试的程序员特定方法。单元测试应用 Selenium WebDriver 框架。Selenium RC 是控制 Web 浏览器的代理。相反，WebDriver 框架使用本机 API 调用来控制 Web 浏览器。您甚至可以运行 HtmlUnit 框架，消除了对真实 Web 浏览器的依赖。这使得测试独立于操作系统，但去除了测试浏览器特定依赖的能力。WebDriver 支持许多不同类型的浏览器。

+   **SoapUI**：这简化了为 Web 服务创建功能测试的过程。该工具可以读取 Web 服务公开的 **WSDL**（Web 服务定义语言）文件，使用该信息生成功能测试的骨架。GUI 使理解过程变得容易。

# 从 Jenkins 部署 WAR 文件到 Tomcat

部署 Web 应用程序进行集成测试的三种主要方法如下：

+   在 Jenkins 作业中启动 Jetty 等容器本地运行 Web 应用程序。应用程序数据库通常是内存中的，并且存储的数据在作业结束后不会持久化。这样可以节省清理工作，并消除对基础设施的不必要依赖。

+   每晚都会创建一个夜间构建，应用程序会通过调度程序重新构建。不需要轮询 SCM。这种方法的优点是团队分布广，确切地知道新构建存在的时间和 URL，以及部署脚本很简洁。

+   部署到应用服务器。首先，在 Jenkins 中打包 Web 应用程序，然后部署准备好由第二个 Jenkins 作业进行测试。这种方法的缺点是，您正在动态替换应用程序，主机服务器可能不会始终稳定地响应。

在此示例中，您将使用 Deploy 插件将 WAR 文件部署到远程 Tomcat 7 服务器。此插件可以在一系列服务器类型和版本范围内部署，包括 Tomcat、GlassFish 和 JBoss。

## 准备就绪

为 Jenkins 安装 Deploy 插件（[`wiki.jenkins-ci.org/display/JENKINS/Deploy+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Deploy+Plugin)）。下载最新版本的 Tomcat 7 并解压缩（[`tomcat.apache.org/download-70.cgi`](http://tomcat.apache.org/download-70.cgi)）。

## 如何做...

1.  为简单的 WAR 文件从命令行创建一个 Maven 项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.simplewar -DartifactId=simplewar -Dversion=1.0-SNAPSHOT -DarchetypeArtifactId=maven-archetype-webapp 

    ```

1.  将新创建的项目提交到您的 Git 或子版本库中。

1.  为避免与监听端口 `8080` 的 Jenkins 冲突，在 Tomcat 根目录下编辑 `conf/server.xml`，将默认连接器端口号更改为 `38887`：

    ```
     <Connector port="38887" protocol="HTTP/1.1" connectionTimeout="20000" redirectPort="8443" />

    ```

1.  从命令行启动 Tomcat：

    ```
    bin/startup.sh

    ```

1.  登录 Jenkins。

1.  创建名为 `ch6.remote.deploy` 的 Maven

1.  在 **源代码管理** 部分，选中 **Subversion** 单选框，将您自己的子版本库 URL 添加到 **Repository URL**。

1.  在**构建**部分，对于**目标和选项**，添加`clean package`。

1.  在**后期构建操作**部分，勾选**部署 war/ear 到容器**，添加以下配置:

    +   **WAR/EAR 文件**: `target/simplewar.war`

    +   **容器**: Tomcat 7.x

    +   **管理器用户名**: `jenkins_build`

    +   **管理器密码**: `mylongpassword`

    +   **Tomcat URL**: `http://localhost:38887`

1.  点击**保存**。

1.  运行构建。

1.  构建将以类似以下的输出失败: **java.io.IOException: 服务器返回 HTTP 响应代码: 401，网址为: http://localhost:38887/manager/text/list**。

1.  通过在`conf/tomcat-users.xml`中添加以下内容，编辑：在`</tomcat-users>`之前：

    ```
    <role rolename="manager-gui"/>
    <role rolename="manager-script"/>
    <role rolename="manager-jmx"/>
    <role rolename="manager-status"/>
    <user username="jenkins_build" password="mylongpassword" roles="manager-gui,manager-script,manager-jmx,manager-status"/>
    ```

1.  重新启动 Tomcat。

1.  在 Jenkins 中，再次构建该任务。现在构建将成功。查看 Tomcat 日志`logs/catalina.out`将显示类似于以下内容的输出: **Oct 06, 2014 9:37:11 PM org.apache.catalina.startup.HostConfig deployWAR**

    **信息: 正在部署 Web 应用程序存档 /xxxxx/apache-tomcat-7.0.23/webapps/simplewar.war**。

1.  使用 Web 浏览器访问`http://localhost:38887/simplewar/`，如下面的屏幕截图所示: ![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_10.jpg)

### 注意

一个可能的陷阱：如果你在后期构建配置中拼错了 WAR 文件的名称，那么它会悄无声息地失败，但构建仍然会成功。

## 工作原理...

在撰写本文时，Deploy 插件部署到以下服务器类型和版本:

+   Tomcat 4.x/5.x/6.x/7.x

+   JBoss 3.x/4.x

+   GlassFish 2.x/3.x

在此示例中，Jenkins 打包了一个简单的 WAR 文件并部署到了 Tomcat 实例。默认情况下，Tomcat 监听`8080`端口，Jenkins 也是如此。通过编辑`conf/server.xml`，将端口移动到了`38887`，避免了冲突。

Jenkins 插件调用 Tomcat Manager。在部署失败且出现`401`未经授权错误([`www.w3.org/Protocols/rfc2616/rfc2616-sec10.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html))后，你创建了一个具有所需角色的 Tomcat 用户。实际上，新用户比部署所需的权限更大。用户有权查看用于监控的 JMX 数据。这会帮助你以后进行调试。

在生产环境中部署时，使用 SSL 连接以避免在网络上传送未加密的密码。

## 还有更多...

启动时，Tomcat 日志会提到缺少 Apache Tomcat 本机库:

**信息: 基于 APR 的 Apache Tomcat 本机库，允许在生产环境中获得最佳性能，在 java.library.path 中找不到: /usr/java/packages/lib/i386:/usr/lib/i386-linux-gnu/jni:/lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/usr/lib/jni:/lib:/usr/lib**。

该库在 Linux 平台上运行时提高了性能，基于 Apache Portable Runtime 项目的努力 ([`apr.apache.org/`](http://apr.apache.org/))。

你可以在`bin/tomcat-native.tar.gz`中找到源代码。构建说明可以在[`tomcat.apache.org/native-doc/`](http://tomcat.apache.org/native-doc/)找到。

## 另请参阅

+   第三章 中的 *为 Jetty 配置集成测试* 配方，*构建软件*

# 创建多个 Jenkins 节点

测试是一个繁重的过程。如果您想要扩展您的服务，那么您需要计划将大部分工作分配给其他节点。

Jenkins 在组织中的一个进化路径是从一个 Jenkins 主节点开始。随着作业数量的增加，我们需要将更重的作业，例如测试，推送到从节点。这使得主节点更轻巧且更专业地聚合结果。还有其他原因可以分配测试，例如当您希望在不同的操作系统下使用不同的网络浏览器或在本机运行 .NET 应用程序时进行功能测试。

此配方使用 Multi slave config 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Multi+slave+config+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Multi+slave+config+plugin)) 在本地安装额外的 Jenkins 节点。它是针对 Linux 的，允许 Jenkins 通过 SSH 安装、配置和控制从节点。

## 准备工作

在 Jenkins 中安装 Multi slave config 插件。您还需要一个 Ubuntu 的测试实例，如 *使用测试 Jenkins 实例* 配方中描述的那样，第一章，*维护 Jenkins*。

## 如何操作...

1.  从从节点的命令行创建用户 `jenkins-unix-nodex`：

    ```
    sudo adduser jenkins-unix-nodex

    ```

1.  使用空密码为主 Jenkins 生成私钥和公共证书：

    ```
    sudo -u jenkins ssh-keygen -t rsa
    Generating public/private rsa key pair.
    Enter file in which to save the key 
    (/var/lib/jenkins/.ssh/id_rsa): 
    Created directory '/var/lib/jenkins/.ssh'.
    Enter passphrase (empty for no passphrase): 
    Enter same passphrase again: 
    Your identification has been saved in 
    /var/lib/jenkins/.ssh/id_rsa.
    Your public key has been saved in 
    /var/lib/jenkins/.ssh/id_rsa.pub

    ```

1.  创建 `.ssh` 目录和 Jenkins 的公共证书到 `.ssh/authorized_keys`。

    ```
    sudo -u jenkins-unix-nodex mkdir /home/jenkins-unix-nodex/.ssh 
    sudo cp /var/lib/jenkins/.ssh/id_rsa.pub /home/jenkins-unix-nodex/.ssh/authorized_keys

    ```

1.  更改 `authorized_keys` 的所有者和组为 `jenkins-unix-nodex`:`jenkins-unix-nodex`：

    ```
    sudo chown jenkins-unix-nodex:jenkins-unix-nodex /home/jenkins-unix-nodex/.ssh/authorized_keys

    ```

1.  测试您是否可以无密码登录到 `jenkins-unix-nodex` 作为 `jenkins`。

    ```
    sudo –u Jenkins ssh jenkins-unix-nodex@localhost
    The authenticity of host 'localhost (127.0.0.1)' can't be established.
    ECDSA key fingerprint is 
    xx:yy:21:zz:46:dd:02:fa:1w:15:27:20:e6:74:3e:a2.
    Are you sure you want to continue connecting (yes/no)? yes
    Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.

    ```

    ### 注意

    您将需要接受密钥指纹。

1.  登录到 Jenkins。

1.  访问凭据存储库（`localhost:8080/credential-store`）。

1.  单击 **全局凭据** 链接，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_03.jpg)

1.  单击 **添加凭据**。

1.  添加以下详细信息：

    +   **类型**：带私钥的 SSH 用户名

    +   **范围**：**全局**

    +   **用户名**：`jenkins-unix-nodex`

    +   **私钥**：**来自 Jenkins 主机的 ~/.ssh**

1.  单击 **保存**。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_01.jpg)

1.  访问 **Manage Jenkins** 下的 **MultiSlave Config Plugin**（`localhost:8080/multi-slave-config-plugin/?`）。

1.  单击 **添加从节点**。

1.  添加到 **使用空格分隔的名称创建从节点**：**unix-node01**，然后单击 **继续**。

1.  在 **Multi Slave Config Plugin – 添加从节点** 屏幕上，添加以下详细信息：

    +   **描述**：**我是一个愚蠢的 Ubuntu 节点**

    +   **执行器数量**：**2**

    +   **远程文件系统根目录**：**/home/jenkins-unix-nodex**

    +   **设置标签**：**unix dumb functional**

1.  选择启动方法为 **通过 SSH 在 Unix 机器上启动从节点** 并添加详细信息：

    +   **主机**：**localhost**

    +   **凭据**：**jenkins-unix-nodex**

1.  点击**保存**。

1.  返回到主页面。 您现在将看到**Build Executor Status**中包含**Master**和**unix-node01**，如下图所示：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_02.jpg)

## 它是如何工作的...

在这个示例中，您已经将一个节点部署到本地*NIX 框中。 使用了第二个用户帐户。 该帐户使用了 Jenkins 用户的公钥以便更轻松地进行管理：Jenkins 现在可以在没有密码的情况下使用`ssh`和`scp`。 

多从节点配置插件可以消除部署从节点的繁琐工作。 它允许您从一个模板从节点复制并部署多个节点。

Jenkins 可以以多种不同的方式运行节点：使用 SSH，主节点运行自定义脚本，或通过 Windows 服务（[`wiki.jenkins-ci.org/display/JENKINS/Distributed+builds`](https://wiki.jenkins-ci.org/display/JENKINS/Distributed+builds)）。 最可靠的方法是通过 SSH 协议。 这种方法的优点是多方面的：

+   使用 SSH 是流行的，意味着对大多数人来说学习曲线较为平缓。

+   SSH 是一种可靠的技术，经过多代人的实践证明其稳健性。

+   大多数操作系统都有 SSH 守护程序，不仅仅是*NIX。 一种选择是在 Windows 上安装 Cygwin（[`www.cygwin.com/`](http://www.cygwin.com/)）并带有一个 SSH 守护程序。

    ### 注意

    如果您希望在 Cygwin 下的 Windows 中运行您的 Unix 脚本，请考虑安装 Cygpath 插件。 该插件将 Unix 样式路径转换为 Windows 样式。 有关更多信息，请访问

    [`wiki.jenkins-ci.org/display/JENKINS/Cygpath+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Cygpath+Plugin)。

配置的节点已分配了三个标签：`unix`，`dumb`和`functional`。 在创建新作业时，检查设置**限制此项目可以运行的位置**并添加其中一个标签，将确保作业在具有该标签的节点上运行。

主节点根据优先级列表计算要运行作业的节点。 除非另有配置，否则在只有主节点时创建的作业仍将在主节点上运行。 新创建的作业默认将在从节点上运行。

当部署多个 Jenkins 节点时，如果您的环境结构保持一致，则可以节省工作量。 考虑使用从相同基本镜像开始的虚拟环境。 CloudBees（[`www.cloudbees.com`](http://www.cloudbees.com)）是一个以部署虚拟实例为中心的商业服务的示例。

### 注意

您可以在[`wiki.jenkins-ci.org/display/JENKINS/Step+by+step+guide+to+set+up+master+and+slave+machines`](https://wiki.jenkins-ci.org/display/JENKINS/Step+by+step+guide+to+set+up+master+and+slave+machines)找到有关为 Jenkins 从节点安装 Windows 服务的更多信息。

## 还有更多...

从版本 1.446 开始（[`jenkins-ci.org/changelog`](http://jenkins-ci.org/changelog)），Jenkins 已经内置了 SSH 守护程序。这将减少编写客户端代码的工作量。命令行界面可以通过 SSH 协议访问。您可以通过 Jenkins 管理网页设置守护程序的端口号，或者将端口号浮动。

Jenkins 使用头部信息发布端口号为 **X-SSH-Endpoint**。要自己查看，请使用 curl（[`curl.haxx.se/`](http://curl.haxx.se/)）查找从 Jenkins 返回的头部信息。例如，对于 *NIX 系统，可以尝试从命令行输入：

```
curl -s -D - localhost:8080 -o /dev/null

```

头部信息被发送到`stdout`供您查看，而正文被发送到`/dev/null`，这是一个系统位置，忽略所有输入。

来自 Jenkins 的响应将类似于以下内容：

```
HTTP/1.1 200 OK
Cache-Control: no-cache,no-store,must-revalidate
X-Hudson-Theme: default
Content-Type: text/html;charset=UTF-8
Set-Cookie: JSESSIONID.bebd81dc=1mkx0f5m97ipsjqhygljrbqmo;Path=/;HttpOnly
Expires: Thu, 01 Jan 1970 00:00:00 GMT
X-Hudson: 1.395
X-Jenkins: 1.583
X-Jenkins-Session: 5c9958f6
X-Hudson-CLI-Port: 39269
X-Jenkins-CLI-Port: 39269
X-Jenkins-CLI2-Port: 39269
X-Frame-Options: sameorigin
X-SSH-Endpoint: localhost:57024
X-Instance-Identity: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjOABhI+cuNtKfu5b46FKGr/IXh9IgaTVgf16QgCmoAR41S00gXJezDRJ1i4tC0tB6Tqz5SuKqcDDxU19fndIe7qhmNOPdAIMUU8i/UmKLC4eY/WfYqE9y4PpIR23yCVd2RB+KzADEhTB/voiLLoEkogj22WtUd7TZWhzRnAW58wrzI6uAWHqOtHvlO7MxFo1AY4ZyXLw202Dz+1tlKkECr5oy9dFyKy3U1lnpilg6snG70AYz+/uFs52FeOl3qkCfDVCGMDHqLEvJJzWsZ5hAv37fEaj1QyMA69joBjesgt1n1CeJeD0cy5+BIkwoHmrGW2VwvrxssIkm3RVhjJbeQIDAQABContent-Length: 19857
Server: Jetty(8.y.z-SNAPSHOT)
```

## 另请参阅

+   第一章中的 *使用测试 Jenkins 实例* 方法，*维护 Jenkins*

+   从节点的*自定义设置脚本*方法

# 从节点的自定义设置脚本

此方法向您展示如何在从节点上运行自己的初始化脚本。这使您可以执行节点系统清理、检查健康状况、设置测试以及执行其他必要的任务。

## 准备工作

要使此方法生效，您需要按照*创建多个 Jenkins 节点*的方法描述安装一个从节点。

您还将安装了从节点设置插件（[`wiki.jenkins-ci.org/display/JENKINS/Slave+Setup+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Slave+Setup+Plugin)）。

## 操作方法...

1.  创建一个名为`ch6.remote.slave.setup`的自由样式作业。

1.  检查**限制**此项目可运行的位置。

1.  在 **标签表达式** 中添加文本`dumb`，如以下截图所示：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_08.jpg)

1.  点击**保存**，然后构建作业。

1.  点击**返回仪表板**。

1.  在**构建执行者状态**下点击**unix-node01**。

1.  点击**脚本控制台**。

1.  将以下文本添加到**脚本控制台**，然后点击**运行**：

    ```
    println "pwd".execute().text
    println "ls ./workspace".execute().text
    ```

1.  创建目录`/var/lib/jenkins/myfiles`。

1.  创建文件`/var/lib/jenkins/myfiles/banner.sh`，内容如下：

    ```
    #!/bin/sh
    echo -------------------------- > slave_banner.txt
    echo THIS IS A SLAVE INIT BANNER  >> slave_banner.txt
    echo WORKING ON SLAVE: ${NODE_TO_SETUP_NAME} >> slave_banner.txt
    date >> slave_banner.txt
    echo SCRIPT DOES SOME WORK HERE >> slave_banner.txt
    echo -------------------------- >> slave_banner.txt
    mv slave_banner.txt  /home/jenkins-unix- nodex/workspace/ch6.remote.slave.setup/
    ```

1.  访问**配置系统**页面（`http://localhost:8080/configure`）。

1.  在**从节点设置**部分，点击**添加**按钮添加**从节点设置列表**。

1.  添加以下细节：

    +   **设置文件目录**：`/var/lib/jenkins/myfiles`

    +   **复制后的设置脚本**：`./banner.sh`

    +   **标签表达式**：`dumb`

    ![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_09.jpg)

1.  检查 **立即保存部署**。

1.  点击**保存**。

1.  运行作业`ch6.remote.slave.setup`。

1.  查看工作空间。您现在将看到一个名为`banner.txt`的文件，内容类似于以下内容：

    ```
    --------------------------
    THIS IS A SLAVE INIT BANNER
    WORKING ON SLAVE: unix-node01
    Tue Oct 14 13:39:09 CEST 2014
    SCRIPT DOES SOME WORK HERE
    --------------------------

    ```

## 工作原理...

您使用从节点设置插件将`banner.sh`从`/var/lib/jenkins`复制到从节点的主目录下的 `banner.sh`。此操作在每次节点上运行作业之前运行。

选择**保存后部署**以确保从节点上获取的脚本是最新的。

你使用脚本控制台发现了节点的主目录位置。你还验证了工作区包含了与`ch6.remote.slave.setup`作业同名的目录。

在作业中，您将其运行限制在具有**dumb**标签的节点上。这样，您就可以确保作业在节点上运行。

`banner.sh`默认使用的是`sh` shell，实际上指向了**Bourne Again Shell** ([`www.gnu.org/software/bash/`](http://www.gnu.org/software/bash/))，或者是**Debian Almquist Shell** ([`gondor.apana.org.au/~herbert/dash/`](http://gondor.apana.org.au/~herbert/dash/))的`dash`。

### 注意

有关在 Ubuntu 中使用破折号的原因，请访问[`wiki.ubuntu.com/DashAsBinSh`](https://wiki.ubuntu.com/DashAsBinSh)。

为了显示已运行，脚本将一个带有时间戳的小横幅输出到`banner.txt`。脚本中的最后一个命令将`banner.txt`移动到节点工作区下的作业目录。

作业运行后，从节点将工作空间复制回 Jenkins 主服务器的工作空间。稍后您会查看结果。

## 还有更多...

如果您的 Jenkins 节点支持其他语言，例如 Perl，您可以通过在脚本的第一行添加`#!`约定，指向脚本语言的二进制完整路径来运行它们。要发现二进制文件的路径，您可以使用节点脚本控制台并运行`which`命令：

```
println "which perl".execute().text
```

这导致了`/usr/bin/perl`。

一个“Hello World”Perl 脚本将如下代码所示：

```
#!/usr/bin/perl
print "Hello World"
```

## 另请参阅

+   *创建多个 Jenkins 节点*配方

# 使用 FitNesse 进行测试

FitNesse ([`fitnesse.org`](http://fitnesse.org))是一个完全集成的独立 wiki 和验收测试框架。您可以在表格中编写测试并运行它们。在 wiki 语言中编写测试扩大了潜在测试编写者的受众，并减少了学习新框架所需的初始工作量。

![使用 FitNesse 进行测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_04.jpg)

如果测试通过，则表格行以绿色显示。如果失败，则以红色显示。测试可以被 wiki 内容包围，以在相同位置提供上下文信息，如用户故事。您还可以考虑在 FitNesse 中创建您的 Web 应用程序的模拟以及将测试指向这些模拟。

本配方描述了如何远程运行 FitNesse 并在 Jenkins 中显示结果。

## 准备工作

从[`fitnesse.org/FitNesseDownload`](http://fitnesse.org/FitNesseDownload)下载最新稳定的 FitNesse JAR。从[`wiki.jenkins-ci.org/display/JENKINS/FitNesse+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/FitNesse+Plugin)安装 Jenkins 的 FitNesse 插件。

### 注意

用于测试此配方的发布号是`20140901`。

## 如何做...

1.  创建目录`fit/logs`并将其放置在`fitnesse-standalone.jar`的`fit`目录中。

1.  从命令行运行 FitNesse 帮助并查看选项：

    ```
    java -jar fitnesse-standalone.jar –help
    Usage: java -jar fitnesse.jar [-vpdrleoab]
    -p <port number> {80}
    -d <working directory> {.}
    -r <page root directory> {FitNesseRoot}
    -l <log directory> {no logging}
    -f <config properties file> {plugins.properties}
    -e <days> {14} Number of days before page versions expire
    -o omit updates
    -a {user:pwd | user-file-name} enable authentication.
    -i Install only, then quit.
    -c <command> execute single command.
    -b <filename> redirect command output.
    -v {off} Verbose logging

    ```

1.  从命令行运行 FitNesse 并查看启动输出：

    ```
    java -jar fitnesse-standalone.jar -p 39996 -l logs -a tester:test
    Bootstrapping FitNesse, the fully integrated standalone wiki and acceptance testing framework.
    root page: fitnesse.wiki.fs.FileSystemPage at ./FitNesseRoot#latest
    logger: /home/alan/Desktop/X/fitness/logs
    authenticator: fitnesse.authentication.OneUserAuthenticator
    page factory: fitnesse.html.template.PageFactory
    page theme: fitnesse_straight
    Starting FitNesse on port: 39996

    ```

1.  使用 web 浏览器，访问`http://localhost:39996`。

1.  单击**验收测试**链接。

1.  单击**套件**链接。这将激活一组测试。根据您的计算机，测试可能需要几分钟才能完成。直接链接是`http://localhost:39996/FitNesse.SuiteAcceptanceTests?suite`。

1.  单击**测试历史记录**链接。您需要以用户`tester`和密码`test`登录。

1.  查看`fit/logs`目录中的日志。再次运行套件后，您现在将看到类似于以下条目：

    ```
    127.0.0.1 - tester [01/Oct/2014:11:14:59 +0100] "GET /FitNesse.SuiteAcceptanceTests?suite HTTP/1.1" 200 6086667

    ```

1.  登录 Jenkins 并创建一个名为`ch6.remote.fitnesse`的自由风格软件项目。

1.  在**构建**部分，从**添加构建步骤**中选择**执行 fitnesse 测试**选项。

1.  检查**FitNesse 实例已运行**选项，并添加：

    +   **FitNesse 主机**：`localhost`

    +   **FitNesse 端口**：`39996`

    +   **目标页面**：`FitNesse.SuiteAcceptanceTests?suite`

    +   检查**目标是否为套件？**选项

    +   **HTTP 超时（毫秒）**：`180000`

    +   **fitnesse xml 结果文件路径**：`fitnesse-results.xml`

1.  在**后构建操作**部分，检查**发布 FitNesse 结果**报告选项。

1.  将值`fitnesse-results.xml`添加到输入**fitnesse xml 结果文件路径**中。

1.  单击**保存**。

1.  运行该任务。

1.  通过点击**FitNesse 结果**链接查看最新的任务。![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_11.jpg)

## 它的工作原理...

FitNesse 有一组内置的验收测试，用于检查自身是否存在回归。Jenkins 插件调用测试，并要求以 XML 格式返回结果，使用 HTTP `GET` 请求的 URL：`http://localhost:39996/FitNesse.SuiteAcceptanceTests?suite&format=xml`。结果看起来类似于以下内容：

```
<testResults>
<FitNesseVersion>v20140901</FitNesseVersion>
<rootPath>FitNesse.SuiteAcceptanceTests</rootPath>
<result>
<counts><right>103</right>
<wrong>0</wrong>
<ignores>0</ignores>
<exceptions>0</exceptions>
</counts>
<runTimeInMillis>27</runTimeInMillis>
<relativePageName>CopyAndAppendLastRow</relativePageName>
<pageHistoryLink>
FitNesse.SuiteAcceptanceTests.SuiteFitDecoratorTests.CopyAndAppendLastRow?pageHistory&resultDate=20141101164526
</pageHistoryLink>
</result>
```

然后，Jenkins 插件解析 XML 并生成报告。

默认情况下，FitNesse 页面上没有启用安全性。在这个示例中，启动时定义了用户名和密码。但是，我们没有进一步定义页面的安全权限。要激活，您需要转到页面左侧的属性链接，并检查`secure-test`的安全权限。

您还可以通过文本文件中的用户列表或 Kerberos/ActiveDirectory 进行身份验证。有关更多详细信息，请查看[`fitnesse.org/FitNesse.FullReferenceGuide.UserGuide.AdministeringFitNesse.SecurityDescription`](http://fitnesse.org/FitNesse.FullReferenceGuide.UserGuide.AdministeringFitNesse.SecurityDescription)。

也有一个为 LDAP 认证贡献的插件：[`github.com/timander/fitnesse-ldap-authenticator`](https://github.com/timander/fitnesse-ldap-authenticator)

### 注意

考虑应用 `深度安全性`：通过防火墙在 FitNesse 服务器上添加 IP 限制可以创建额外的防御层。例如，你可以在 wiki 前面放置一个 Apache 服务器，并启用 SSL/TLS 来确保密码加密。一个比 Apache 更轻量的替代方案是 Nginx：[`wiki.nginx.org`](http://wiki.nginx.org)。

## 还有更多...

你可以在其 GitHub 主页上找到有关构建最新版本 FitNesse 的源代码信息：[`github.com/unclebob/fitnesse`](https://github.com/unclebob/fitnesse)

如果你喜欢 FitNesse，为什么不参与社区讨论呢？你可以订阅它的 Yahoo 群组 `<fitnesse-subscribe@yahoogroups.com>`，然后在 `<fitnesse@yahoogroups.com.>` 发布消息。Yahoo 的使用准则讨论了一般礼仪：[`info.yahoo.com/guidelines/us/yahoo/groups/`](http://info.yahoo.com/guidelines/us/yahoo/groups/)

## 另请参阅

+   *激活 FitNesse HtmlUnit fixtures* 教程

# 激活 FitNesse HtmlUnit fixtures

FitNesse 是一个可扩展的测试框架。可以编写自己的测试类型，称为 fixtures，并通过 FitNesse 表调用新的测试类型。这允许 Jenkins 运行不同于现有测试的替代测试。

此教程向你展示了如何集成使用 HtmlUnit fixture 的功能测试。同样的方法也适用于其他 fixtures。

## 准备工作

此教程假设你已经执行了 *使用 FitNesse 进行测试* 教程。

## 如何操作...

1.  访问 [`sourceforge.net/projects/htmlfixtureim/`](http://sourceforge.net/projects/htmlfixtureim/)，下载并解压缩 `HtmlFixture-2.5.1`。

1.  将 `HtmlFixture-2.5.1/lib` 目录移动到 `FitNesseRoot` 目录下。

1.  将 `HtmlFixture-2.5.1/log4j.properties` 复制到 `FitNesseRoot/log4j.properties`。

1.  启动 FitNesse：

    ```
    java -jar fitnesse-standalone.jar -p 39996 -l logs -a tester:test

    ```

1.  在网络浏览器中访问 `http://localhost:39996/root?edit`，添加以下内容，将 `FitHome` 替换为你的 Fitnesse 服务器主目录的完全限定路径：

    ```
    !path /FitHome/FitNesseRoot/lib/*
    !fixture com.jbergin.HtmlFixture 
    ```

1.  访问 `http://localhost:39996`。在左侧菜单中，点击 **编辑**。

1.  在页面底部添加文本 `ThisIsMyPageTest`。

1.  点击 **保存**。

1.  点击新的 **ThisIsMyPageTest** 链接。

1.  点击 **工具** 按钮。

1.  选择 **属性**。

1.  点击 **页面类型** 测试。

1.  一个弹出窗口会询问你的 **用户名** 和 **密码**。输入 `tester` 和 `test`。

1.  你将被返回到 **ThisisMyPageTest** 页面；点击 **保存**。

1.  点击左侧菜单上的 **编辑** 按钮。

1.  在以 `!contents` 开头的行后添加以下内容：

    ```
    |Import|
    |com.jbergin|
    '''STORY'''
    This is an example of using HtmlUnit:http://htmlunit.sourceforge.net/
    '''TESTS'''
    !|HtmlFixture|
    |http://localhost:8080/login| Login||
    |Print Cookies||
    |Print Response Headers||
    |Has Text|log in|
    |Element Focus|search-box|input|
    |Set Value|ch5||
    |Focus Parent Type|form|/search/||
    ```

1.  点击 **保存**。

1.  点击 **测试**。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_06.jpg)

1.  在 Jenkins 中 **新建任务** 下，从 `ch6.remote.fitness` 复制 **现有任务** / **复制** 到 **任务名称** `ch6.remote.fitness_fixture`。

1.  在 **构建** 部分，下面的 **目标** | **目标页面** 将 `FitNesse.SuiteAcceptanceTests` 替换为 `ThisIsMyPageTest`。

1.  不勾选 **目标是否为套件？**。

1.  点击 **Save**。

1.  运行任务。由于额外的调试信息与结果一起发送，导致 Jenkins 插件解析器混淆而失败。

1.  访问测试页面 `http://localhost:39996/ThisIsMyPageTest?edit`，用以下代码替换测试表格的内容：

    ```
    !|HtmlFixture|
    |http://localhost:8080/login| Login|
    |Has Text|log in|
    |Element Focus|search-box|input|
    |Set Value|ch5|
    |Focus Parent Type|form|/search/|
    ```

1.  再次运行 Jenkins 任务。现在结果将被解析。

## 工作原理...

Fixture 是用 Java 编写的。通过将下载的库放置在 FitNesse 的 `lib` 目录中，使它们可访问。然后在根页面中定义类路径和夹具位置，允许在启动时加载夹具。有关更多详细信息，请查看文件 `HtmlFixture-2.5.1/README`。

接下来，你使用 wiki 的 CamelCase 笔记法创建了链接到不存在的 **ThisIsMyPageTest** 页面。然后添加了一个 HtmlUnit 夹具测试。

首先，你需要导入夹具，其库路径在 Root 页面中定义：

```
|Import|
|com.jbergin|
```

接下来，添加了一些示例描述性 wiki 内容以显示你可以创建一个故事而不影响测试。最后，添加了测试。

表格 `!|HtmlFixture|` 的第一行定义要使用的夹具。第二行存储要测试的位置。

打印命令，如 `Print Cookies` 或 `Print Response` `Headers` 返回有助于构建测试的信息。

如果你不确定一系列可接受的命令，则故意制造语法错误，命令将作为结果返回。例如：

```
|Print something||
```

`Has Text` 命令是一个断言，如果返回页面的文本中找不到 `log in` 则失败。

通过聚焦到特定元素然后 `Set Value`，你可以向表单添加输入。

在测试期间，如果你想要显示特定请求的返回内容，则需要三列；例如，第一行显示返回的页面，第二行则不显示：

```
|http://localhost:8080/login| Login||
|http://localhost:8080/login| Login|
```

将 HTML 页面作为结果的一部分返回，为 Jenkins 插件提供了需要解析的额外信息。这容易出错。因此，在第 19 步中，你移除了额外的列，确保可靠的解析。

可以在 [`htmlfixtureim.sourceforge.net/documentation.shtml`](http://htmlfixtureim.sourceforge.net/documentation.shtml) 找到此夹具的完整文档。

## 还有更多...

FitNesse 有可能增加 Jenkins 可执行的远程测试的词汇量。有几个有趣的夹具需要审查：

+   **RestFixture 用于 REST 服务**：

    [`github.com/smartrics/RestFixture/wiki`](https://github.com/smartrics/RestFixture/wiki)

+   **使用 Selenium 进行基于 Web 的功能测试的 Webtestfixtures**：

    [`sourceforge.net/projects/webtestfixtures/`](http://sourceforge.net/projects/webtestfixtures/)

+   **DBfit 可以帮助你测试数据库**：

    [`gojko.net/fitnesse/dbfit/`](http://gojko.net/fitnesse/dbfit/)

## 另请参阅

+   *使用 FitNesse 进行测试* 配方

# 运行 Selenium IDE 测试

Selenium IDE 允许你在 Firefox 中记录你在网页中的点击操作，并重放它们。这对于功能测试非常有用。测试计划以 HTML 格式保存。

这个示例展示了如何使用 Maven 和 Jenkins 自动重放测试。它使用内存中的 X 服务器 **Xvfb** ([`en.wikipedia.org/wiki/Xvfb`](http://en.wikipedia.org/wiki/Xvfb))，这样 Firefox 就可以在无头服务器上运行。Maven 使用 Selenium RC 运行测试，然后充当测试和浏览器之间的代理。虽然我们使用 Firefox 进行录制，但你也可以使用其他类型的浏览器运行测试。

随着 Selenium 2.0 的发布，Selenium 服务器现在具有内置的网格功能 ([`code.google.com/p/selenium/wiki/Grid2`](https://code.google.com/p/selenium/wiki/Grid2))。本章不讨论这个功能，只是说明 Selenium 网格允许你在多个操作系统上并行运行 Selenium 测试。

## 准备工作

安装 Selenium HTML 报告插件 ([`wiki.jenkins-ci.org/display/JENKINS/seleniumhtmlreport+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/seleniumhtmlreport+Plugin)) 和 EnvInject 插件 ([`wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin))。同时需要 Xvfb 和 Firefox。在 Ubuntu Linux 环境中安装 Xvfb 运行 `sudo apt-get install xvfb`。

### 注意

在 Jenkins 插件管理器中，该插件称为环境注入器插件，而在 Wiki 中称为 EnvInject 插件。这可能会让人感到困惑，但两个名称都属于同一个插件。

## 如何操作...

1.  从命令行创建一个简单的 Maven 项目：

    ```
    mvn archetype:generate -DgroupId=nl.berg.packt.selenium -DartifactId=selenium_html -DarchetypeArtifactId=maven-archetype-quickstart -Dversion=1.0-SNAPSHOT

    ```

1.  在新创建的 `pom.xml` 文件中，在 `</project>` 标签之前添加以下 `build` 部分：

    ```
    <build>
        <plugins>
         <plugin>
          <groupId>org.codehaus.mojo</groupId>
          <artifactId>selenium-maven-plugin</artifactId>
          <version>2.3</version>              
           <executions>
            <execution>
              <id>xvfb</id>
              <phase>pre-integration-test</phase>
              <goals>
                 <goal>xvfb</goal>
              </goals>
             </execution>
             <execution>
                <id>start-selenium</id>
                <phase>integration-test</phase>
             <goals>
             <goal>selenese</goal> 
            </goals>
           <configuration> <suite>src/test/resources/selenium/TestSuite.xhtml</suite>
         <browser>*firefox</browser>                        
         <multiWindow>true</multiWindow>
         <background>true</background>                           <results>./target/results/selenium.html</results> <startURL>http://localhost:8080/login/</startURL>
          </configuration>
         </execution>
        </executions>
       </plugin>
      </plugins>
    </build>
    ```

1.  创建 `src/test/resources/log4j.properties` 文件，并添加以下内容：

    ```
    log4j.rootLogger=INFO, A1
    log4j.appender.A1=org.apache.log4j.ConsoleAppender
    log4j.appender.A1.layout=org.apache.log4j.PatternLayout
    log4j.appender.A1.layout.ConversionPattern=%-4r [%t] %-5p %c %x - %m%n
    ```

1.  创建目录 `src/test/resources/selenium`。

1.  创建文件 `src/test/resources/selenium/TestSuite.xhtml`，并添加以下内容：

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html  xml:lang="en" lang="en">
    <head>
      <meta content="text/html; charset=UTF-8" http-equiv="content-type" />
      <title>My Test Suite</title>
    </head>
    <body>
    <table id="suiteTable" cellpadding="1" cellspacing="1" border="1" class="selenium"><tbody>
    <tr><td><b>Test Suite</b></td></tr>
    <tr><td><a href="MyTest.xhtml">Just pinging Jenkins Login Page</a></td></tr>
    </tbody></table>
    </body>
    </html>
    ```

    HTML 将会渲染成以下截图：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_12.jpg)

1.  创建测试文件 `src/test/resources/selenium/MyTest.xhtml`，并添加以下内容：

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html  xml:lang="en" lang="en">
    <head profile="http://selenium-ide.openqa.org/profiles/test-case">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>MyTest</title>
    </head><body>
    <table cellpadding="1" cellspacing="1" border="1">
    <thead>
    <tr><td rowspan="1" colspan="3">MyTest</td></tr>
    </thead><tbody>
    <tr><td>open</td><td>/login?from=%2F</td><td></td></tr>
    <tr><td>verifyTextPresent</td><td>log in</td><td></td></tr>
    </tbody></table></body></html>
    ```

    HTML 将会按照以下截图进行渲染：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_13.jpg)

1.  从命令行运行 Maven 项目，验证构建是否成功，如下所示：

    ```
    mvn clean integration-test –Dlog4j.configuration=file./src/test/resources/log4j.properties

    ```

1.  运行 `mvn clean` 然后提交项目到你的 Subversion 仓库。

1.  登录到 Jenkins 并创建一个名为 `ch6.remote.selenium_html` 的 Maven 作业。

1.  在 **Global** 部分（配置页面顶部），勾选 **Prepare an environment for the job** 并添加 `DISPLAY=:20` 到 **Properties Content**。

1.  在 **Source Code Management** 部分，勾选 **Subversion**，并将你的 Subversion URL 添加到 **Repository URL**。

1.  在 **build** 部分，将 `clean integration-test –Dlog4j.configuration=file./src/test/resources/log4j.properties` 添加到 **Goals and options**。

1.  在**后构建操作**部分，勾选**发布 Selenium HTML 报告**。

1.  将`target/results`添加到**Selenium 测试结果位置**。

1.  检查**如果解析结果文件时发生异常，则将构建结果状态设置为失败**。

1.  单击**保存**。

1.  运行作业，查看结果，如下图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_14.jpg)

## 工作原理...

创建了一个原始的 Selenium IDE 测试套件，包含两个 HTML 页面。第一个`TestSuite.xhtml`定义了套件，其中包含指向测试的 HTML 链接。我们只在`MyTest.xhtml`中定义了一个测试。

该测试访问本地 Jenkins 的登录页面，并验证**登录**文本是否存在。

`pom.xml`文件定义了启动和关闭 Xvfb 服务器的阶段。默认配置是让 Xvfb 在`DISPLAY 20`上接受输入。

Maven 假设 Xvfb 二进制文件已安装，并且不尝试将其作为依赖项下载。对于 Firefox 浏览器也是如此。这样做会导致一个脆弱的特定于操作系统的配置。在复杂的 Jenkins 环境中，这种依赖项最有可能失败。自动化功能测试必须具有显著的优势，以抵消增加的维护工作量。

选项`Multiwindow`设置为 true，因为测试在它们自己的 Firefox 窗口中运行。选项`Background`设置为 true，以便 Maven 在后台运行测试。结果存储在相对位置`./target/results/selenium.html`，准备供 Jenkins 插件解析。有关 Selenium-Maven-plugin 的更多信息，请访问[`mojo.codehaus.org/selenium-maven-plugin/`](http://mojo.codehaus.org/selenium-maven-plugin/)。

Jenkins 作业将`DISPLAY`变量设置为`20`，以便 Firefox 在 Xvfb 中呈现。然后运行 Maven 作业并生成结果页面。然后 Jenkins 插件解析结果。  

增加自动功能测试的可靠性的两种方法是：

+   使用 HtmlUnit，它不需要特定于操作系统的配置。但是，您将失去执行跨浏览器检查的能力。

+   运行 WebDriver 而不是 Selenium RC。WebDriver 使用本地 API 调用，功能更可靠。与 Selenium RC 一样，WebDriver 可以针对多种不同的浏览器类型运行。

下一个示例将展示如何使用 WebDriver 和 HtmlUnit 进行单元测试。

## 还有更多...

在我的开发 Jenkins Ubuntu 服务器上，运行此示例的作业失败了。原因是 Maven 插件对 Selenium 的依赖项不喜欢由自动更新脚本安装的新版本 Firefox。解决问题的方法是在 Jenkins 主目录下安装一个已知工作的 Firefox 二进制文件，并在`pom.xml`文件中直接指向该二进制文件，将`<browser>*firefox</browser>`替换为`<browser>*firefox Path</browser>`。

这里，`Path`类似于`/var/lib/Jenkins/firefox/firefox-bin`。

另一个问题的原因是需要为 Firefox 创建一个自定义配置文件，其中包含停止弹出窗口或拒绝自签名证书的辅助插件。有关更完整的信息，请参阅：[`docs.seleniumhq.org/docs/`](http://docs.seleniumhq.org/docs/)

### 注意

Firefox 的替代方案是 Chrome。有一个 Jenkins 插件可以帮助在 Jenkins 节点上部署 Chrome ([`wiki.jenkins-ci.org/display/JENKINS/ChromeDriver+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/ChromeDriver+plugin))。

在 Maven `pom.xml` 文件中，您将不得不将浏览器更改为 `*chrome`。

## 另请参见

+   使用 Selenium WebDriver 触发失败安全集成测试的方法

# 使用 Selenium WebDriver 触发失败安全集成测试

单元测试是程序员保护其代码免受回归的自然方式。单元测试轻量且易于运行。编写单元测试应该像编写打印语句一样容易。JUnit ([`www.junit.org/`](http://www.junit.org/)) 是 Java 的流行单元测试框架，另一个是 TestNG ([`testng.org/doc/index.html`](http://testng.org/doc/index.html))。

此方案使用 WebDriver 和 HtmlUnit 与 TestNG 结合编写简单的自动化功能测试。使用 HtmlUnit 而不是真正的浏览器可以创建稳定的与操作系统无关的测试，虽然它们不测试浏览器兼容性，但可以发现大多数功能失败。

## 准备工作

创建一个项目目录。查看 Maven 编译器插件文档 ([`maven.apache.org/plugins/maven-compiler-plugin/`](http://maven.apache.org/plugins/maven-compiler-plugin/))。

## 如何做...

1.  创建带有以下内容的 `pom.xml`：

    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <project  
      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
        <modelVersion>4.0.0</modelVersion>
        <groupId>nl.uva.berg</groupId>
        <artifactId>integrationtest</artifactId>
        <version>1.0-SNAPSHOT</version>
        <build> 
          <plugins>
            <plugin>
              <groupId>org.apache.maven.plugins</groupId>
              <artifactId>maven-compiler-plugin</artifactId>
                <version>2.3.2</version>
            </plugin>
          <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-failsafe-plugin</artifactId>
            <version>2.10</version>
        </plugin>
        </plugins>
      </build>
      <dependencies>
        <dependency>
          <groupId>org.testng</groupId>
            <artifactId>testng</artifactId>
            <version>6.1.1</version>
            <scope>test</scope>
      </dependency>
      <dependency>
        <groupId>org.seleniumhq.selenium</groupId>
        <artifactId>selenium-htmlunit-driver</artifactId>
        <version>2.15.0</version>
      </dependency>
      </dependencies>
    </project>
    ```

1.  通过添加以下内容的 `TestIT.java` 文件创建名为 `src/test/java/nl/berg/packt/webdriver` 的目录：

    ```
    package nl.berg.packt.webdriver;

    import org.openqa.selenium.WebDriver;
    import org.openqa.selenium.htmlunit.HtmlUnitDriver;
    import org.testng.Assert;
    import org.testng.annotations.*; 
    import java.io.File;
    import java.io.IOException;

    public class TestIT {
      private static final String WEBPAGE = "http://www.google.com";
      private static final String TITLE = "Google";
      private WebDriver driver;

      @BeforeSuite
      public void creatDriver(){
        this.driver= new HtmlUnitDriver(true);
      }

      @Test
      public void getLoginPageWithHTMLUNIT() throws IOException, InterruptedException {
          driver.get(WEBPAGE);
          System.out.println("TITLE IS ==>\""+driver.getTitle()+"\"");
        Assert.assertEquals(driver.getTitle(), TITLE);
      }

      @AfterSuite
      public void closeDriver(){
        driver.close();
      }
    }
    ```

1.  在顶级项目目录中，运行 `mvn clean verify`。构建应该成功，并输出类似于以下内容：

    ```
    TITLE IS ==>"Google"
    Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 4.31 sec
    Results :
    Tests run: 1, Failures: 0, Errors: 0, Skipped: 0

    ```

1.  将代码提交到您的子版本库。

1.  登录 Jenkins 并创建名为 `ch6.remote.driver` 的新的 maven 项目。

1.  在 **Source Code Management** 部分，勾选 **Subversion**。

1.  在 **Modules** | **Repository URL** 下，添加本地子版本库的位置。

1.  在 **Goals and options** 的 **build** 部分中，添加 `clean verify`。

1.  单击 **保存**。

1.  运行该作业。成功构建后，您将看到一个指向**最新测试结果**的链接，详细说明功能测试情况。

## 它是如何工作的...

Maven 使用 Failsafe 插件 ([`maven.apache.org/surefire/maven-failsafe-plugin/`](http://maven.apache.org/surefire/maven-failsafe-plugin/)) 运行集成测试。如果其 `integration-test` 阶段包含故障，则插件不会导致构建失败。相反，它允许运行 `post-integration-test` 阶段，以执行拆卸任务。

`pom.xml` 文件提到了两个依赖项：一个是 TestNG，另一个是 HtmlUnit 驱动程序。如果要使用真正的浏览器，则需要定义它们的 Maven 依赖项。

有关 Failsafe 插件如何与 TestNG 框架配合使用的详细信息，请参阅 [`maven.apache.org/plugins/maven-failsafe-plugin/examples/testng.html`](http://maven.apache.org/plugins/maven-failsafe-plugin/examples/testng.html)

Java 类使用注解来定义代码将在单元测试周期的哪个部分调用。`@BeforeSuite` 在测试套件开始时调用 WebDriver 实例的创建。`@AfterSuite` 在测试运行结束后关闭驱动程序。`@test` 定义方法为一个测试。

测试访问 Google 页面并验证标题的存在。HtmlUnit 注意到返回的 Google 页面和资源中的样式表和 JavaScript 存在一些错误；然而，断言成功。

示例测试的主要弱点是未能将断言与网页导航分开。考虑根据网页创建 Java 类（[`code.google.com/p/selenium/wiki/PageObjects`](https://code.google.com/p/selenium/wiki/PageObjects)）。页面对象返回其他页面对象。然后，在单独的类中运行测试断言，将返回的页面对象的成员与预期值进行比较。这种设计模式支持更高程度的可重用性。

### 提示

支持页面对象架构的 Groovy 中的优秀框架是**Geb**（[`www.gebish.org/`](http://www.gebish.org/)）。

## 还有更多……

大脑处理的所有感官信息的 80% 通过眼睛传递。一张图片可以节省一千字的描述性文本。WebDriver 有捕获屏幕截图的能力。例如，以下代码对于 Firefox 驱动程序将截图保存到 `loginpage_firefox.png`：

```
public void getLoginPageWithFirefox() throws IOException, InterruptedException {
  FirefoxDriver driver = new FirefoxDriver();
  driver.get("http://localhost:8080/login); 
 FileUtils.copyFile(driver.getScreenshotAs(OutputType.FILE), new File("loginpage_firefox.png"));
  driver.close();
}
```

### 注意

不幸的是，HtmlUnit 驱动程序不会创建截图：[`code.google.com/p/selenium/issues/detail?id=1361`](http://code.google.com/p/selenium/issues/detail?id=1361)。

然而，您可以在 [`groups.google.com/forum/#!msg/selenium-developers/PTR_j4xLVRM/k2yVq01Fa7oJ`](https://groups.google.com/forum/#!msg/selenium-developers/PTR_j4xLVRM/k2yVq01Fa7oJ) 找到一个实验性更新。

## 另见

+   *运行 Selenium IDE 测试*食谱

+   *激活 FitNesse HtmlUnit 夹具*食谱

# 创建 JMeter 测试计划

JMeter（[`jmeter.apache.org`](http://jmeter.apache.org)）是一个用于压力测试的开源工具。它允许您可视化地创建测试计划，然后根据该计划对系统进行测试。

JMeter 可以进行多种类型的请求，称为**采样器**。它可以对 HTTP、LDAP 和数据库进行采样，使用脚本等等。它可以通过**监听器**进行可视化报告。

### 注意

有关 JMeter 的入门书籍是：《Apache JMeter》作者 Emily H. Halili，由 Packt Publishing 出版，ISBN 1847192955（[`www.packtpub.com/beginning-apache-jmeter`](http://www.packtpub.com/beginning-apache-jmeter)）。

同一出版商出版的另外两本更高级的书籍是 [`www.packtpub.com/application-development/performance-testing-jmeter-29`](https://www.packtpub.com/application-development/performance-testing-jmeter-29) 和 [`www.packtpub.com/application-development/jmeter-cookbook-raw`](https://www.packtpub.com/application-development/jmeter-cookbook-raw)。

在这个示例中，您将编写一个用于访问网页的测试计划，这些网页的 URL 在文本文件中定义。在下一个示例中，*报告 JMeter 测试计划*，您将配置 Jenkins 运行 JMeter 测试计划。

## 准备工作

下载并解压现代版本的 JMeter。（[`jmeter.apache.org/download_jmeter.cgi`](http://jmeter.apache.org/download_jmeter.cgi)）。JMeter 是一个 Java 应用程序，因此将在正确安装了 Java 的任何系统上运行。

## 如何实现...

1.  创建子目录 `plans` 和 `example`。

1.  创建一个 CSV 文件 `./data/URLS.csv`，内容如下：

    ```
    localhost,8080,/login
    localhost,9080,/blah
    ```

1.  运行 JMeter GUI—例如，`./bin/jmeter.sh` 或 `jmeter.bat`，根据操作系统而定。GUI 将启动一个新的测试计划。

1.  右键单击 **测试计划**，然后选择 **添加** | **线程（用户）** | **线程组**。

1.  将 **线程数（用户数）** 更改为 **2**。

1.  右键单击 **测试计划**，然后选择 **添加** | **配置元素** | **CSV 数据文件设置**。添加以下细节：

    +   **文件名**：CSV 文件的完整路径

    +   **变量名称（逗号分隔）**：`HOST`、`PORT`、`URL`

    +   **分隔符（使用 '\t' 表示制表符）**：`,`

1.  右键单击 **测试计划**，然后选择 **添加** | **配置元素** | **HTTP Cookie 管理器**。

1.  右键单击 **测试计划**，然后选择 **添加** | **监听器** | **查看树状结果**。

1.  右键单击 **线程组**，然后选择 **添加** | **采样器** | **HTTP 请求**。添加以下细节：

    +   **名称**：`${HOST}:${PORT}${URL}`

    +   **服务器名称或 IP**：`${HOST}`

    +   **端口号**：`${PORT}`

    +   在 **可选任务** 下，勾选 **从 HTML 文件中检索所有嵌入资源**

1.  点击 **测试计划** 然后 **文件** | **保存**。将测试计划保存为 `example/jmeter_example.jmx`。

1.  按下 *Ctrl* + *R* 运行测试计划。

1.  点击 **查看结果树** 并查看响应：![如何实现...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_15.jpg)

1.  将此项目提交到您的 Subversion 存储库。

## 工作原理...

JMeter 使用线程并行运行请求。每个线程应该大约模拟一个用户。实际上，真实用户对系统的影响远远小于线程。线程可以每秒击中系统多次，而通常用户大约每二十秒点击一次。

测试计划使用了许多元素：

+   **线程组**：这定义了运行的线程数。

+   **Cookie 管理器**：这个元素用于每个线程跟踪 cookie。如果您想在请求之间通过 cookie 跟踪，请确保使用这个元素。例如，如果一个线程登录到一个 Tomcat 服务器，需要为每个线程存储唯一的 `Jsessionid`。

+   **CSV Data Set Config**：此元素解析 CSV 文件的内容，并将值放入`HOST`、`PORT`和`URL`变量中。每个迭代每个线程读取 CSV 文件的一行。使用`${variable_name}`表示法在元素中展开变量。

+   **查看结果树**：此监听器将结果显示在 GUI 中，以请求和响应的树形式显示。这对调试很有用，但稍后应该将其删除。

一个常见的错误是假设一个线程等同于一个用户。主要区别在于线程的响应速度可能比平均用户快。如果在请求中不添加延迟因素，那么您可能会使用少量线程来让您的应用程序负荷过重。例如，阿姆斯特丹大学的在线系统每次点击的典型延迟为 25 秒。

### 提示

如果您想要诱发应用程序中的多线程问题，则使用随机延迟元素而不是常量延迟。这也更好地模拟了典型用户交互。

## 还有更多...

考虑将用户代理和其他浏览器标头存储在文本文件中，然后通过 CSV Data Set Config 元素选择这些值进行 HTTP 请求。如果返回给您的 Web 浏览器的资源（如 JavaScript 或图像）取决于用户代理，则这是有用的。然后，JMeter 可以循环遍历用户代理，断言资源存在。

## 另请参阅

+   报告 JMeter 性能指标 的示例

+   使用 JMeter 断言进行功能测试 的示例

# 报告 JMeter 性能指标

在这个示例中，将向您展示如何配置 Jenkins 来运行 JMeter 测试计划，然后收集和报告结果。还将解释如何从 Ant 脚本传递变量到 JMeter。

## 准备就绪

假设您已经按照上一个示例创建了 JMeter 测试计划。您还需要安装 Jenkins 性能插件 ([`wiki.jenkins-ci.org/display/JENKINS/Performance+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Performance+Plugin))。

## 如何做...

1.  在 JMeter 中打开`./examples/jmeter_example.jmx`，并另存为`./plans/URL_ping.jmx`。

1.  选择**CSV Data Set Config**，将**Filename**更改为`${__property(csv)}`。

1.  在**文件**菜单下选择**保存**选项。

1.  在项目的顶层创建一个`build.xml`文件，并添加以下内容：

    ```
    <project default="jmeter.tests">
    <property name="jmeter" location="/var/lib/jenkins/jmeter" />
    <property name="target" location="${basedir}/target" />   
    <echo message="Running... Expecting variables [jvarg,desc]" />
    <echo message="For help please read ${basedir}/README"/>
    <echo message="[DESCRIPTION] ${desc}" />
    <taskdef  name="jmeter"  classname="org.programmerplanet.ant.taskdefs.jmeter.JMeterTask" classpath="${jmeter}/extras/ant-jmeter-1.0.9.jar" />
          <target name="jmeter.init">
          <mkdir  dir="${basedir}/jmeter_results"/>
          <delete includeemptydirs="true">
          <fileset dir="${basedir}/jmeter_results" includes="**/*" />
          </delete>
        </target>
        <target name="jmeter.tests" depends="jmeter.init" description="launch jmeter load tests">
        <echo message="[Running] jmeter tests..." />
    <jmeter jmeterhome="${jmeter}" resultlog="${basedir}/jmeter_results/LoadTestResults.jtl">
        <testplans dir="${basedir}/plans" includes="*.jmx"/>
        <jvmarg value="${jvarg}" />
        <property name="csv" value="${basedir}/data/URLS.csv" />
        </jmeter>
      </target>
    </project>
    ```

1.  将更新提交到您的 Subversion 项目。

1.  登录 Jenkins。

1.  使用名称为`ch6.remote.jmeter`的新自由风格任务。

1.  在**源代码管理**下，勾选**Subversion**，并将您的 Subversion 仓库 URL 添加到**Repository URL**中。

1.  在**构建**部分中，添加构建步骤**Invoke Ant**。

1.  点击新的**Invoke Ant**子部分中的**高级**，并添加属性：

    ```
    jvarg=-Xmx512m
    desc= This is the first iteration in a performance test environment – Driven by Jenkins
    ```

1.  在**后构建操作**部分，勾选**发布性能测试结果报告**。将输入`jmeter_results/*.jtl`添加到**报告文件**中。

1.  点击**保存**。

1.  运行作业几次并查看在 **性能趋势** 链接下找到的结果。

## 它是如何工作的...

`build.xml` 文件是一个 Ant 脚本，用于设置环境，然后调用库 `/extras/ant-jmeter-1.0.9.jar` 中定义的 JMeter Ant 任务。该 JAR 文件作为标准 JMeter 发行版的一部分安装。

找到 `plans` 目录下的任何 JMeter 测试计划都将被运行。将测试计划从 `examples` 目录移动到 `plans` 目录将其激活。结果将汇总在 `jmeter_results/LoadTestResults.jtl` 中。

Ant 脚本将 `csv` 变量传递给 JMeter 测试计划；CSV 文件的位置为 `${basedir}/data/URLS.csv`。 `${basedir}` 是由 Ant 自动定义的。顾名思义，它是 Ant 项目的基目录。

你可以在 JMeter 元素中使用结构 `${__functioncall(parameters)}` 调用 JMeter 函数。你已经将函数调用 `${__property(csv)}` 添加到测试计划 CSV Data Set Config 元素中。该函数引入了在 Ant 脚本中定义的 `csv` 的值。

Jenkins 作业运行 Ant 脚本，Ant 脚本然后运行 JMeter 测试计划并汇总结果。然后 Jenkins 性能插件解析结果，生成报告。

## 还有更多...

要快速构建复杂的测试计划，请考虑使用内置于 JMeter 中的透明代理 ([`jmeter.apache.org/usermanual/component_reference.html#HTTP_Proxy_Server`](http://jmeter.apache.org/usermanual/component_reference.html#HTTP_Proxy_Server))。你可以在本地机器上的给定端口上运行它，并设置浏览器中的代理首选项以匹配。然后，记录的 JMeter 元素将为您提供捕获请求中发送的参数的很好的概念。

一个替代方案是 **BadBoy** ([`www.badboysoftware.biz/docs/jmeter.htm`](http://www.badboysoftware.biz/docs/jmeter.htm))，它有自己的内置网络浏览器。它允许您以与 Selenium IDE 类似的方式记录操作，然后保存到 JMeter 计划中。

## 另请参阅

+   *创建 JMeter 测试计划* 的方法

+   *使用 JMeter 断言进行功能测试* 的方法

# 使用 JMeter 断言进行功能测试

此方法将向您展示如何在 Jenkins 作业中使用 JMeter 断言。JMeter 可以通过断言测试其 HTTP 请求和其他采样器的响应。这使得 JMeter 可以基于一系列 JMeter 测试来使 Jenkins 构建失败。当从 HTML 应用程序的底层代码快速变化时，这种方法尤其重要。

测试计划登录到您的本地 Jenkins 实例并检查登录响应中的大小、持续时间和文本。

## 准备工作

我们假设您已经执行了 *创建 JMeter 测试计划* 和 *报告 JMeter 性能指标* 的方法。

### 注意

该配方需要在 Jenkins 中创建一个名为 `tester1` 的用户。随意更改用户名和密码。记得在不再需要时删除测试用户。

## 如何操作...

1.  在 Jenkins 中创建名为 `tester1` 的用户，密码为 `testtest`。

1.  运行 JMeter。在**测试计划**元素中将**名称**更改为 `LoginLogoutPlan`，为**用户定义变量**添加：

    +   **名称**：`用户`，**值**：`tester1`

    +   **名称**：`密码`，**值**：`testtest`

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_16.jpg)

1.  在**测试计划**上右键单击，然后选择**添加** | **配置元件** | **HTTP Cookie 管理器**。

1.  在**测试计划**上右键单击，然后选择**添加** | **监听器** | **查看树形结果**。

1.  在**测试计划**上右键单击，然后选择**添加** | **线程（用户）** | **线程组**。

1.  在**线程组**上右键单击，然后选择**添加** | **取样器** | **HTTP 请求**，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_17.jpg)

1.  将以下细节添加到**HTTP 请求取样器**中：

    +   **名称**：`/j_aceqi_security_check`

    +   **服务器名称或 IP**：`localhost`

    +   **端口号**：`8080`

    +   **路径**：`/j_aceqi_security_check`

1.  在**发送请求参数**部分中添加：

    +   **名称**：`j_username`，**值**：`${USER}`

    +   **名称**：`j_password`，**值**：`${PASS}`

1.  在**线程组**上右键单击，然后选择**添加** | **取样器** | **HTTP 请求**。

1.  将以下细节添加到**HTTP 请求取样器**中。如有必要，拖放新创建的元素，使其位于 `/j_acegi_security_check` 之后。

1.  将以下细节添加到**HTTP 请求取样器**中：

    +   **名称**：`/logout`

    +   **服务器名称或 IP**：`localhost`

    +   **端口号**：`8080`

    +   **路径**：`/logout`

1.  将测试计划保存到位置 `./plans/LoginLogoutPlan_without_assertions.jmx`。

1.  将更改提交到您的本地 SVN 仓库。

1.  在 Jenkins 中运行先前创建的作业 `ch6.remote.jmeter`。注意，在**性能报告**链接中，`/j_acegi_security_check` HTTP 请求取样器成功。

1.  将 `./plans/LoginLogoutPlan_without_assertions.jmx` 复制到 `./plans/LoginLogoutPlan.jmx`。

1.  在 JMeter 中编辑 `./plans/LoginLogoutPlan.jmx`。

1.  在 JMeter 元素 `j_acegi_security_check` 上右键单击，选择**添加** | **断言** | **持续时间断言**。

1.  在新创建的断言中，将**持续时间（毫秒）**设置为 `1000`。

1.  在 JMeter 元素 `j_acegi_security_check` 上右键单击，选择**添加** | **断言** | **大小断言**。

1.  在新创建的断言中，将**字节大小**设置为 `40000`，并将**比较类型**设置为 **<**。

1.  在 JMeter 元素 `j_acegi_security_check` 上右键单击，选择**添加** | **断言** | **响应断言**，并填写细节：

    +   在**应用于**部分中检查**仅主样本**

    +   在**要测试的响应字段**部分中检查**文本响应**

    +   在**模式匹配规则**部分中检查**包含**

    +   对于**要测试的模式**添加 **<title>仪表板 [Jenkins]</title>**

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_18.jpg)

1.  保存测试计划并提交到您的本地子版本库。

1.  运行 JMeter（*Ctrl* + *R*）并查看 **查看结果树**。请注意，大小和响应断言失败。

1.  在 Jenkins 中运行先前创建的作业 `ch6.remote.jmeter`。注意，在 **性能报告** 链接中 `/j_acegi_security_check` 也会失败。

## 工作原理...

上一个配方中的脚手架没有改变。在 `plans` 目录下找到的任何 JMeter 测试计划都会在运行 Jenkins 作业时调用。

你创建了一个新的测试计划，其中包含两个 HTTP 请求采样器。第一个采样器将变量 `j_username` 和 `j_password` 提交到登录 URL `/j_acegi_security_check`。响应包含一个包含有效会话 ID 的 cookie，该 ID 被存储在 cookie 管理器中。还添加了三个断言元素作为 HTTP 请求登录采样器的子项。如果其中任何一个断言失败，则 HTTP 请求结果也会失败。在 Jenkins 中，您可以根据可定义的阈值配置作业以失败或警告的方式运行。

三个断言对于测试计划来说是典型的。它们是：

+   对返回结果的大小进行断言。大小不应大于 40,000 字节。

+   对持续时间进行断言。如果响应时间太长，那么您就有了一个需要进一步检查的性能回归。

+   最强大的断言用于检查文本模式。—在这种情况下，查看返回标题的详细信息。JMeter 元素还可以根据正则模式解析文本。

## 还有更多...

JMeter 具有使用请求进行压力测试的能力。每秒钟发出一个请求的 200 个线程大致相当于同时登录到一个应用程序的 5,000 个用户，每 25 秒点击一次。一个粗略的经验法则是，一个站点在一年中最繁忙的时间内约有 10% 的成员登录到应用程序中。因此，每秒点击一次的 200 个线程适合总成员数为 50,000 的站点。

了解使用模式也很重要；您对系统的使用了解越少，您就需要建立更宽的安全边界。为额外的容量进行计划不是不寻常的。额外的容量可能会成为您是否度假的差异。

### 注意

为了扩展其负载生成能力，JMeter 具有运行多个 JMeter 从节点的能力。有关此主题的官方教程，请参阅：[`jmeter.apache.org/usermanual/jmeter_distributed_testing_step_by_step.pdf`](http://jmeter.apache.org/usermanual/jmeter_distributed_testing_step_by_step.pdf)

## 另请参阅

+   *创建 JMeter 测试计划* 配方

+   *报告 JMeter 性能指标* 配方

# 启用 Sakai web 服务

Sakai CLE 是全球许多大学使用的应用程序。基于超过一百万行的 Java 代码，Sakai CLE 允许学生与在线课程和项目站点进行交互。它赋予教师轻松创建这些站点的权限。

在这个示例中，您将启用 Web 服务并编写自己的简单 ping 服务。在下一个示例中，您将为这些服务编写测试。

## 准备就绪

您可以在[`sakaiproject.org`](http://sakaiproject.org)找到到最新下载的链接。

从[`source.sakaiproject.org/release/2.8.1`](http://source.sakaiproject.org/release/2.8.1)下载并解压 Sakai CLE 版本 2.8.1。

最新版本可以在[`source.sakaiproject.org/release`](http://source.sakaiproject.org/release)找到。

请注意，服务器在第一次启动时所需的时间比后续启动要长。这是由于样例课程的初始创建。

## 如何做...

1.  编辑`sakai/sakai.properties`以包含：

    ```
    webservices.allowlogin=true
    webservices.allow=.*
    webservices.log-denied=true
    ```

1.  在 NIX 系统中，从根文件夹`./start-sakai.sh`运行 Sakai，或者在 Windows 中运行`./start-sakai.bat`。如果 Jenkins 或另一个服务正在端口`8080`上运行，Sakai 将无法启动，并显示：

    ```
    2012-01-14 14:09:16,845 ERROR main 
    org.apache.coyote.http11.Http11BaseProtocol - Error starting endpoint
    java.net.BindException: Address already in use:8080

    ```

1.  停止 Sakai `./stop-sakai.sh` 或者 `./stop-sakai.bat`。

1.  将端口号移动到`39955`，例如修改`conf/server.xml`文件：

    ```
    <Connector port="39955" maxHttpHeaderSize="8192" URIEncoding="UTF-8" maxThreads="150" minSpareThreads="25" maxSpareThreads="75" enableLookups="false" redirectPort="8443" acceptCount="100" connectionTimeout="20000" disableUploadTimeout="true" />
    ```

1.  在 NIX 系统中，从根文件夹`./start-sakai.sh`运行 Sakai，或者在 Windows 中运行`./start-sakai.bat`。

    ### 注意

    第一次启动可能需要很长时间，因为演示数据被填充到内置数据库中。

1.  在 Web 浏览器中访问`http://localhost:39955/portal`。

1.  以`admin`用户登录，密码为`admin`。

1.  注销。

1.  访问`http://localhost:39955/sakai-axis/SakaiScript.jws?wsdl`。

1.  通过将以下内容添加到`./webapps/sakai-axis/PingTest.jws`来创建一个简单的未经身份验证的 Web 服务：

    ```
    public class PingTest {
      public String ping(String ignore){
        return "Insecure answer =>"+ignore;
      }
      public String pong(String ignoreMeAsWell){
        return youCantSeeMe();}
      private String  youCantSeeMe(){
        return "PONG";
      }
    }
    ```

1.  要验证服务是否可用，请访问`http://localhost:39955/sakai-axis/PingTest.jws?wsdl`。

1.  要验证 REST 服务是否可用，请访问`http://localhost:39955/direct`。

## 它是如何工作的...

Sakai 软件包是自包含的，拥有自己的数据库和 Tomcat 服务器。它的主要配置文件是`sakai/sakai.properties`。您已经更新了它以允许从任何地方使用 Web 服务。在实际部署中，IP 地址受到更严格的限制。

为了避免与本地 Jenkins 服务器端口冲突，修改了 Tomcat 的`conf/server.xml`文件。

Sakai 同时具有 REST 和 SOAP Web 服务。您将在`/direct`URL 下找到 REST 服务。许多服务在`/direct/describe`下描述。服务向下提供一级。例如，要创建或删除用户，您需要使用在`/direct/user/describe`中描述的用户服务。

REST 服务使用 Sakai 框架注册到 Entitybroker ([`confluence.sakaiproject.org/display/SAKDEV/Entity+Provider+and+Broker`](https://confluence.sakaiproject.org/display/SAKDEV/Entity+Provider+and+Broker))。Entitybroker 确保服务之间的一致处理，节省了编码工作量。Entitybroker 负责以正确的格式提供服务信息。要以 XML 格式查看 Sakai 认为您当前是谁，请访问`http://localhost:39955/direct/user/current.xml`，要以 JSON 格式查看，请用`current.xml`替换为`current.json`。

SOAP 服务基于 Apache AXIS 框架 ([`axis.apache.org/axis/`](http://axis.apache.org/axis/))。要创建一个新的基于 SOAP 的 Web 服务，您可以将一个扩展名为`.jws`的文本文件放入`webapps/sakai-axis`目录中。Apache AXIS 在第一次调用时即时编译代码。这样可以实现快速应用程序开发，因为调用者可以立即看到对文本文件的任何修改。

`PingTest`包含一个没有包的类。类名与去除`.jws`扩展名的文件名相同。任何公共方法都会成为 Web 服务。如果访问`http://localhost:39955/sakai-axis/SakaiScript.jws?wsdl`，您会注意到`youCantSeeMe`方法没有公开; 这是因为它具有私有范围。

大多数有趣的 Web 服务都需要通过`/sakai-axis/SakaiLogin.jws`登录 Sakai，方法是`login`并传递`username`和`password`作为字符串。返回的字符串是一个 **GUID**（一个由字母和数字组成的长随机字符串），需要将其传递给其他方法以证明身份验证。

在交易结束时登出，使用方法`logout`并传递 GUID。

## 还有更多...

Sakai CLE 不仅仅是一个学习管理系统，它还是一个使开发新工具变得简单的框架。

新 Sakai 开发人员的程序员咖啡厅位于以下 URL：[`confluence.sakaiproject.org/display/BOOT/Programmer%27s+Cafe`](https://confluence.sakaiproject.org/display/BOOT/Programmer%27s+Cafe)

基于程序员咖啡厅的训练营定期在 Sakai 会议上或通过咨询活动进行。训练营指导开发人员使用 Eclipse 作为首选的标准 IDE 来创建他们的第一个 Sakai 工具。

您可以在[`www.packtpub.com/sakai-cle-courseware-management-for-elearning-research/book`](http://www.packtpub.com/sakai-cle-courseware-management-for-elearning-research/book)找到书籍*Sakai CLE 课程管理：官方指南*，*Packt Publishing*。

### 注意

另一个相关产品是 Apereo **开放学术环境**（**OAE**）[`www.oaeproject.org/`](http://www.oaeproject.org/)。

Apereo OAE，就像 Sakai 一样，是社区驱动的。它具有独特的功能，例如能够在多个组织中同时运行，每个组织看起来都不同，并且可以根据配置的组在组织之间搜索文档或不搜索文档。

## 另请参阅

+   *使用 SoapUI 编写测试计划*示例

+   *报告 SoapUI 测试结果*示例

# 使用 SoapUI 编写测试计划

SoapUI（[`www.soapui.org/`](http://www.soapui.org/)）是一个工具，允许高效地编写功能、性能和安全性测试，主要用于 Web 服务。

在本示例中，您将使用 SoapUI 对上一示例中创建的 Sakai SOAP Web 服务进行基本功能测试。

## 准备工作

如前一示例所述，我们假设您的 Sakai CLE 在端口`39955`上运行，并且`PingTest`服务可用。

要下载并安装 SoapUI，请访问[`www.soapui.org/getting-started/installing-soapui/installing-on-windows.html`](http://www.soapui.org/getting-started/installing-soapui/installing-on-windows.html)并按照安装说明进行操作。

要使 Linux 软件包与旧版本的 SoapUI 配合使用，您可能需要取消注释 SoapUI 启动脚本中的以下行：

```
JAVA_OPTS="$JAVA_OPTS -Dsoapui.jxbrowser.disable=true"
```

### 注意

此示例已针对 SoapUI 的 5.0.0 版本进行了测试。

## 如何操作...

1.  启动 SoapUI。

1.  右键单击**项目**，然后选择**新建 Soap 项目**。

1.  在对话框中填写以下详细信息：

    +   **项目名称**：`SakaiSoapTests`

    +   **初始 WSDL/WADL**：`http://localhost:39955/sakai-axis/PingTest.jws?wsdl`

    ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_19.jpg)

1.  勾选**创建测试套件**。

1.  点击**确定**。

1.  点击**确定**以生成**测试套件**对话框。

1.  点击**确定**以创建**测试套件**。

1.  在左侧导航器中，单击**PingTestSoapBinding TestSuite**旁边的**+**图标。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_20.jpg)

1.  点击**ping TestCase**旁边的**+**图标。

1.  点击**测试步骤（1）**旁边的**+**图标。

1.  右键单击**ping**，然后选择**打开编辑器**。

1.  在编辑器顶部，点击**添加断言**图标 ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_21.jpg)。

1.  选择**断言包含**，然后点击**确定**。

1.  对于**内容**选择`NOT IN TEXT`，然后点击**确定**。

1.  在左侧导航中，右键单击**PingTestSoapBinding TestSuite**，然后选择**显示测试套件编辑器**。

1.  在编辑器中点击**开始测试**图标 ![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_22.jpg)。

1.  查看结果。**ping TestCase**由于断言而失败，而**pong TestCase**成功。

1.  创建名为`src/test/soapui`的目录。

1.  右键单击**SakaiSoapTest**，然后在目录`src/test/soapui`中**另存项目为**`SakaiSoapTests-soapui-project.xml`。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_23.jpg)

## 工作原理...

SoapUI 让制作 Soap 服务的测试套件变得简单。SoapUI 使用`PingTest` WSDL 文件来发现服务的详细信息。

WSDL 代表 **Web Services Description Language** ([`www.w3.org/TR/wsdl`](http://www.w3.org/TR/wsdl))。 生成一个包含有关 `PingTest` 服务位置和使用信息的 XML 文件。

从 WSDL 文件中，SoapUI 为 `Ping` 和 `Pong` 服务创建了一个基本测试。 您在 `Ping` 服务下添加了一个断言，检查 SOAP 响应中是否存在文本 `NOT IN TEXT`。 由于文本确实存在，断言失败。

SoapUI 具有广泛的断言，它可以强制执行，包括检查 Xpath 或 Xquery 匹配，检查状态码，或由自定义脚本测试的断言。

最后，项目以 XML 格式保存，准备在下一个配方的 Maven 项目中重用。

## 还有更多...

SoapUI 不仅仅是 Web 服务的功能测试。 它通过检查边界输入执行安全性测试。 它还具有用于压力测试的负载运行程序。

另一个重要功能是它能够从 WSDL 文件构建模拟服务。 这允许在 Web 服务仍在开发中时在本地构建测试。 早期创建的测试减少了到达生产环境的缺陷数量，降低了成本。 您可以在 [`www.soapui.org/Service-Mocking/mocking-soap-services.html`](http://www.soapui.org/Service-Mocking/mocking-soap-services.html) 找到模拟服务的优秀介绍。

## 另请参阅

+   *启用 Sakai Web 服务* 配方

+   *报告 SoapUI 测试结果* 配方

# 报告 SoapUI 测试结果

在这个配方中，您将创建一个 Maven 项目，该项目运行上一个配方中创建的 SoapUI 测试。 使用 xUnit 插件 ([`wiki.jenkins-ci.org/display/JENKINS/xUnit+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/xUnit+Plugin)) 的 Jenkins 项目将解析结果并生成详细报告。

## 准备工作

安装 Jenkins xUnit 插件。 运行 *启用 Sakai Web 服务* 和 *使用 SoapUI 编写测试计划* 配方。 现在你已经拥有运行 Sakai CLE 和一个准备好使用的 SoapUI 测试计划。

要尝试最新版本的 Maven 插件，请访问 [`www.soapui.org/Test-Automation/maven-2x.html`](http://www.soapui.org/Test-Automation/maven-2x.html)

## 如何做...

1.  创建一个项目目录。 在项目的根目录下，添加一个包含以下内容的 `pom.xml` 文件：

    ```
    <project 

      xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
      <modelVersion>4.0.0</modelVersion>
      <name>Ping regression suite</name>
      <groupId>test.soapui</groupId>
      <artifactId>test.soapui</artifactId>
      <version>1.0-SNAPSHOT</version>
      <packaging>jar</packaging>
      <description>Sakai webservices test</description>
    <pluginRepositories>
      <pluginRepository>
        <id>eviwarePluginRepository</id>
        <url>http://www.eviware.com/repository/maven2/</url>
      </pluginRepository>
    </pluginRepositories>
      <build>
        <plugins>
          <plugin>
            <groupId>eviware</groupId>
            <artifactId>maven-soapui-plugin</artifactId>
            <version>4.0.1</version>
            <executions>
              <execution>
                <id>ubyregression</id>
                <goals>
              <goal>test</goal>
            </goals>
            <phase>test</phase>
          </execution>
        </executions>
        <configuration>
    <projectFile>src/test/soapui/SakaiSoapTests-soapui-project.xml</projectFile>
      <host>localhost:39955</host> <outputFolder>${project.build.directory}/surefire-reports</outputFolder>
              <junitReport>true</junitReport>
              <exportwAll>true</exportwAll>
              <printReport>true</printReport>
            </configuration>
          </plugin>
        </plugins>
      </build>
    </project>
    ```

1.  确保您已将 SoapUI 项目正确放置在 `src/test/soapui/SakaiSoapTests-soapui-project.xml`。

1.  从命令行运行：

    ```
    mvn clean test

    ```

1.  登录 Jenkins。

1.  创建一个名为 `ch6.remote.soapui` 的 Maven 项目。

1.  在 **源代码管理** 部分，检查 **Subversion**，添加您的 **仓库 URL**。

1.  在 **构建** 部分，下 **目标和选项**，添加 `clean test`。

1.  在 **后构建操作** 部分，检查 **发布测试工具结果报告**。

1.  单击 **添加** 按钮。

1.  选择 **JUnit**。

1.  在 **JUNIT 模式** 下添加 `**/target/surefire-reports/TEST-PingTestSoapBinding_TestSuite.xml`。

1.  单击 **保存**。

1.  运行作业。

1.  点击 **Latest Test Result** 链接。您将看到一个失败和一个成功的作业，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_06_24.jpg)

1.  您将在 `http://localhost:8080/job/ch6.remote.soapui/ws/target/surefire-reports/PingTestSoapBinding_TestSuite-ping_TestCase-ping-0-FAILED.txt` 找到失败的完整细节。

## 工作原理...

Maven 项目使用了 maven-soapui `plugin` ([`www.soapui.org/Test-Automation/maven-2x.html`](http://www.soapui.org/Test-Automation/maven-2x.html))。由于插件在主要的 Maven 仓库之一中不可用，您必须配置它以使用 `eviwarePluginRepository` 仓库。

SoapUI 插件被配置为从项目文件 `src/test/soapui/SakaiSoapTests-soapui-project.xml` 中获取其计划，并将结果保存到 `project.build.directory` 相对于工作空间的根目录。

设置的选项是：

```
<junitReport>true</junitReport>
<exportwAll>true</exportwAll>
<printReport>true</printReport>
```

`junitReport` 设置为 `true` 告诉插件创建一个 JUnit 报告。`exportwAll` 设置为 `true` 意味着所有测试的结果都会被导出，而不仅仅是错误。这个选项在调试阶段很有用，除非您有严重的磁盘空间限制，否则应该设置为 `on`。`printReport` 设置为 `true` 确保 Maven 发送一个小的测试报告到控制台，输出类似于：

**SoapUI 4.0.1 TestCaseRunner 概要**

**-----------------------------**

**总测试套件数：1**

**总测试用例数：2（1 个失败）**

**总请求断言数：1**

**总失败断言数：1**

**总导出结果数：1**

**[ERROR] java.lang.Exception: Not Contains in [ping] failed;**

**[响应包含令牌 [不安全的答案 =>？]]**

ping 测试用例失败，因为断言失败。pong 测试用例成功，因为服务存在。因此，即使没有断言，使用 SoapUI 的自动生成功能也可以快速生成一个框架，确保所有服务都在运行。随着项目的发展，您始终可以稍后添加断言。

创建 Jenkins 任务很简单。xUnit 插件允许您导入许多类型的单元测试，包括从 Maven 项目创建的 JUnit 测试。在第 10 步中设置位置为 `**/target/surefire-reports/TEST-PingTestSoapBinding_TestSuite.xml`。

### 提示

自定义报告选项是另一种将自定义数据引入并显示其在 Jenkins 中的历史趋势的方法。它通过使用自定义样式表解析插件找到的 XML 结果来实现。这使您可以灵活地添加自己的定制结果。

## 还有更多...

ping 服务很危险，因为它不过滤输入，输入通过输出反射回来。

许多网络应用程序使用 Web 服务将内容加载到页面中，以避免重新加载整个页面。一个典型的例子是当你输入搜索词并且替代建议即时显示时。通过一点社会工程魔法，受害者最终会发送一个包含脚本的请求到 Web 服务。在返回响应时，脚本将在客户端浏览器中运行。这绕过了同源策略的初衷（[`en.wikipedia.org/wiki/Same_origin_policy`](http://en.wikipedia.org/wiki/Same_origin_policy)）。这被称为非持久性攻击，因为脚本不会持久存储。

对于 XSS 攻击，Web 服务比网页更难测试。幸运的是，SoapUI 简化了测试流程，使其达到了可控制的水平。你可以在[`www.soapui.org/Security/working-with-security-tests.html`](http://www.soapui.org/Security/working-with-security-tests.html)找到关于 SoapUI 安全测试的入门教程。

## 另请参阅

+   *启用 Sakai Web 服务* 配方

+   *使用 SoapUI 编写测试计划* 配方
