# 现代化遗留的 PHP 应用（二）

> 原文：[`zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3`](https://zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：编写测试

此时，我们的遗留应用程序已经部分现代化，以至于我们所有现有的类都在一个中心位置。这些类现在使用依赖注入摆脱了`global`和`new`。现在应该为这些类编写测试，以便如果我们需要更改它们，我们知道它们的现有行为仍然完好无损。

# 对抗测试的抵抗

我们可能不急于现在花时间编写测试。我们不想失去我们正在感受到的前进动力。正当我们相信我们正在取得一些真正的进展时，停下来编写测试感觉就像是在做无用功。这会削弱我们对长期以来一直受苦的糟糕代码库进行一系列改进的乐趣。

对于不愿意编写测试的抵抗是可以理解的。我自己也是一个对自动化测试转变缓慢的人。如果一个人不习惯编写测试，那么编写测试的行为会感到陌生、不熟悉、具有挑战性和无效。很容易说，我可以看到代码是有效的，因为应用程序是有效的。

然而，如果我们不编写测试，我们就注定要在以后不断地遭受痛苦。我们正在使我们的遗留应用程序变得更糟：当我们更改应用程序的某一部分时，我们会感到恐惧，因为我们不知道更改会导致应用程序的其他部分出现什么问题。

因此，尽管编写测试可能很糟糕，但“已编写测试”也是很棒的。这很棒，因为当我们对类进行更改时，我们可以运行自动化测试套件，它会立即告诉我们在更改后是否有任何问题。

# 测试之道

即使我们已经熟悉编写测试，围绕测试的所有戒律也可能令人生畏：

+   不要与文件系统交互；而是构建一个虚拟文件系统。

+   不要与数据库交互；而是构建一组数据夹具。

+   重写你的类，使用接口而不是具体类，并为所有依赖项编写测试替身。

这些都是使测试看起来像是一个不可逾越的挑战的教条命令。当其他事情都做完时，当然我们可以稍后再构建我们的测试！问题是，永远不会有一刻是其他事情都做完了，因此测试永远不会出现。

作为对测试戒律的解药，我建议遵循*测试之道*（[`www.artima.com/weblogs/viewpost.jsp?thread=203994`](http://www.artima.com/weblogs/viewpost.jsp?thread=203994)）。*测试之道*的核心信息是更多的测试因果报应，少一些测试戒律。

这些是我们需要从*测试之道*中了解的关于现代化我们的遗留应用程序的主要观点：

+   测试的最佳时机是在代码刚写好的时候。

+   编写需要编写的测试。

+   今天的不完美测试比将来某一天的完美测试更好。

+   今天写你能写的测试。

类中的代码已经陈旧。毕竟，那些代码是遗留应用程序的一部分。但是现在，我们已经花了很多时间重新组织类，并使用依赖注入来替换它们的`global`和`new`关键字，这些类中的代码在我们的思想中又变得新鲜起来。现在是写这些类的测试的时候了，因为它们的操作仍然在最近的记忆中。

我们不应该被困扰于编写符合测试戒律的适当单元测试。相反，我们应该尽力编写最好的测试，即使测试不完美：

+   如果我们可以编写一个表征测试，只检查输出如何，那么我们应该这样做。

+   如果我们可以编写与数据库、网络或文件系统交互的功能或集成测试，那么我们应该这样做。

+   如果我们可以编写一个松散的单元测试，结合具体类，那么我们应该这样做。

+   如果我们可以编写严格的单元测试，使用测试替身完全隔离被测试的类，那么我们应该这样做。

随着我们在测试中变得更加熟练，一个不完美的测试可以得到完善。一个不存在的测试根本无法得到完善。

我们将尽可能快地编写我们可以编写的测试。等待编写测试只会增加反对编写测试的惯性。代码在我们的脑海中会变得更加陈旧，使得编写测试变得更加困难。今天编写测试将给我们一种成就感，并增加我们编写测试的惯性。

## 设置测试套件

本书的范围并不包括完全解释编写测试的技术和方法。相反，我们将简要总结设置自动化测试套件和编写简单测试所涉及的过程。有关 PHP 测试的更全面的处理，请参阅*The Grumpy Programmer's PHPUnit Cookbook*（[`grumpy-phpunit.com/`](http://grumpy-phpunit.com/)）by *Chris Hartjes*。

### 安装 PHPUnit

PHP 领域有许多不同的测试系统，但最常用的是 PHPUnit。我们需要在开发和测试服务器上安装 PHPUnit，以便编写和执行我们的测试。完整的安装说明在 PHPUnit 网站上。

通过 Composer 安装 PHPUnit 的一种简单方法是：

```php
**$ composer global require phpunit/phpunit=~4.5**

```

另一种方法是直接安装 PHPUnit 的`.phar`：

```php
**$ wget https://phar.phpunit.de/phpunit.phar**
**$ chmod +x phpunit.phar**
**$ sudo mv phpunit.phar /usr/local/bin/phpunit**

```

### 创建一个 tests/目录

安装 PHPUnit 后，我们需要在我们的遗留应用程序中创建一个`tests/`目录。名称和位置并不那么重要，重要的是目的和位置是明显的。最明显的地方可能是在遗留应用程序的根目录，尽管它不应该直接被浏览器访问。

在`tests/`目录中，我们需要创建一个以我们的中心类目录位置命名的子目录。如果我们所有的应用程序类都在一个名为`classes/`的目录中，那么我们应该有一个`tests/classes/`目录。我们的测试结构的想法是模仿我们的应用程序类的结构。

除了`tests/classes/`子目录之外，`tests/`目录还应包含两个文件。第一个是`bootstrap.php`文件，PHPUnit 在运行时将执行该文件。它的目的是帮助设置测试的执行环境。默认情况下，PHPUnit 不会使用应用程序的自动加载器代码，因此创建和注册自动加载器是`bootstrap.php`文件的经典用法。以下是一个使用之前章节中的自动加载器的示例：

```php
**tests/bootstrap.php**
1 <?php
2 require "../classes/Mlaphp/Autoloader.php";
3 $loader = new \Mlaphp\Autoloader;
4 spl_autoload_register(array($loader, 'load'));
5 ?>
```

还在`tests/`目录中，我们需要创建一个`phpunit.xml`文件。这告诉 PHPUnit 如何引导自己以及测试的位置：

```php
**tests/phpunit.xml**
1 <phpunit bootstrap="./bootstrap.php">
2 <testsuites>
3 <testsuite>
4 <directory>./classes</directory>
5 </testsuite>
6 </testsuites>
7 </phpunit>
```

创建`tests/`目录及其内容后，我们的遗留应用程序目录结构应该如下所示：

```php
**/path/to/app/**

```

```php
classes/        # our central class directory location
Auth.php        # class Auth { ... }
Db.php          # class Db { ... }
Mlaphp/
Autoloader.php  # A hypothetical autoloader class
Role.php        # class Role { ... }
User.php        # class User { ... }
foo/
bar/
baz.php         # a page script
includes/       # a common "includes" directory
setup.php       # setup code
index.php       # a page script
tests/          # tests directory
bootstrap.php   # phpunit bootstrap code
classes/        # test cases
phpunit.xml     # phpunit setup file
```

### 选择一个要测试的类

现在我们已经有了一个`tests/`目录，我们实际上可以为我们的应用程序类之一编写一个测试。开始的最简单方法是选择一个没有依赖项的类。此时，我们应该对代码库足够熟悉，以至于知道哪些类有依赖项，哪些没有。如果找不到没有依赖项的类，我们应该选择依赖项最少或依赖项最简单的类。

我们想要在这里*从小处着手*并取得一些早期的成功。每一次成功都会给我们继续进行更大、更复杂的测试的动力和动机。这些小的成功将累积成最终的大成功：一组经过全面测试的类。

### 编写一个测试用例

假设我们选择了一个名为`Foo`的类，它没有依赖项，并且有一个名为`doSomething()`的方法。现在我们将为这个类的方法编写一个测试。

首先，在我们的`tests/classes/`目录中创建一个骨架测试文件。它的位置应该模仿被测试的类的位置。我们在类名后面添加`Test`，并扩展`PHPUnitFramework_TestCase_`，以便我们可以访问测试类中的各种`assert*()`方法：

```php
**tests/classes/FooTest.php**
1 <?php
2 class FooTest extends \PHPUnit_Framework_TestCase
3 {
4 }
5 ?>
```

如果我们现在尝试用 `phpunit` 运行测试，测试将会失败，因为它里面没有测试方法：

```php
**tests $ phpunit**
**PHPUnit 3.7.30 by Sebastian Bergmann.**
**Configuration read from tests/phpunit.xml**
**F**
**Time: 45 ms, Memory: 2.75Mb**
**There was 1 failure:**
**1) Warning**
**No tests found in class "FooTest".**
**FAILURES!**
**Tests: 1, Assertions: 0, Failures: 1.**
**tests $**

```

信不信由你，这都没问题！正如《测试之道》所告诉我们的那样，我们在测试通过时感到高兴，测试失败时也同样如此。这里的失败告诉我们 PHPUnit 成功找到了我们的测试类，但在该类中没有找到任何测试。这告诉我们接下来该做什么。

下一步是为被测试类的公共方法添加一个测试方法。所有测试方法都以单词 `test` 开头，因此我们将使用名为 `testDoSomething()` 的方法来测试 `doSomething()` 方法。在其中，我们将创建一个 `_Foo_` 类的实例，调用它的公共 `doSomething()` 方法，并断言它的实际输出与我们期望的输出相同：

```php
**tests/classes/FooTest.php**
1 <?php
2 class FooTest extends \PHPUnit_Framework_TestCase
3 {
4 public function testDoSomething()
5 {
6 $foo = new Foo;
7 $expect = 'Did the thing!';
8 $actual = $foo->doSomething();
9 $this->assertSame($expect, $actual);
10 }
11 }
12 ?>
```

现在我们可以再次用 `phpunit` 运行我们的测试套件。只要 `doSomething()` 方法返回字符串 `Did the thing!`，我们的测试就会通过。

```php
**tests $ phpunit**
**PHPUnit 3.7.30 by Sebastian Bergmann.**
**Configuration read from tests/phpunit.xml**
**.**
**Time: 30 ms, Memory: 2.75Mb**
**OK (1 test, 1 assertion)**
**tests $**

```

我们为我们的测试通过而感到高兴！

如果 `doSomething()` 返回任何不同的东西，那么测试将会失败。这意味着如果我们在后续工作中更改了 `doSomething()`，我们将知道它的行为已经改变。我们会为它的失败感到高兴，知道我们在进入生产之前就捕捉到了一个 bug，然后修复代码，直到所有测试都通过。

### 做……当

在编写通过的测试后，我们将其提交到版本控制并推送到我们的中央仓库。我们继续为应用程序类中的每个公共方法编写测试，一边编写一边提交和推送。当应用程序类中的所有公共方法都有通过的测试时，我们选择另一个类进行测试，并从头开始一个新的测试类。

## 常见问题

### 我们可以跳过这一步，以后再做吗？

不。

### 真的吗，我们可以以后再做这个吗？

我明白。我真的明白。在我们现代化过程的这一点上，测试似乎没有回报。如果整个章节都没有说服你测试的好处，那么我现在也没什么别的可以说服你的了。如果你想跳过这一步，无论你在这里读到什么建议，你都会跳过它。

所以让我们假设我们在这一点上避免测试的理由是完全合理的，并且与我们特定的情境相适应。考虑到这一点，让我们看看如果现在做不到，那么在项目过程中我们可以做些什么来完成这些测试。继续下一章（不建议！），然后承诺执行以下一个或多个选项：

1.  每天至少完成一个新的测试类。

1.  每次在代码库中使用一个方法时，都要检查是否有针对它的测试。如果没有，就在使用该方法之前编写一个测试。

1.  在修复 bug 或构建功能时，创建一个在任务过程中使用的方法列表，然后在任务完成后为这些方法编写测试。

1.  当我们添加一个新的类方法时，为其编写相应的测试。

1.  将测试编写的工作委托给另一个开发人员，也许是一名初级开发人员。然后我们可以享受现代化的“乐趣”，而初级开发人员可以承担编写测试的看似无聊的工作，但要小心……很快，初级开发人员将比我们更了解代码库。

这些选项让我们能够建立一个测试套件，并且仍然感觉自己在其他方面取得了进展。创建一个自动化测试套件是现代化遗留应用程序的一个不可妥协的方面。现在就编写测试，或者在进行过程中编写，但尽早编写，而不是晚些时候。

### 那些难以测试的类怎么办？

即使依赖注入已经就位，遗留应用程序中的一些类仍然很难编写测试。类的测试可能会有很多难点，我无法在本书中充分解决这些问题。请参考以下作品：

+   *Michael Feathers*的*与遗留代码有效工作*。书中的示例都是用 Java 编写的，但情况与 PHP 中的情况类似。Feathers 展示了如何打破依赖关系，引入接缝，以及改进遗留类的可测试性。

+   Fowler 等人的重构。这本书也使用 Java 作为示例，但由于 Adam Culp 的贡献，我们将相同的示例转换为了 PHP。与 Fowler 的《企业应用架构模式》一样，重构书将为您提供一种词汇来描述您可能已经知道如何做的事情，同时还会向您介绍新的技术。

这些出版物中的信息将帮助我们改进我们的类的质量，而不改变类的行为。

### 我们之前的特性测试呢？

我们根据本章写的测试可能不是替代先决条件章节中现有特性测试的替代品。拥有两组测试很可能是一种祝福，而不是诅咒。在某个时候，特性测试可能会被转换为供 QA 团队使用的验收测试。在那之前，不妨偶尔运行两组测试。

### 我们应该测试私有和受保护的方法吗？

可能不会。这其中有一些教条主义的原因，我在这里不会详细说明，但简而言之：检查类的内部工作过于深入的测试会变得难以处理。

相反，我们应该只测试我们类的公共方法。这些方法暴露的任何行为可能是我们关心的唯一行为。这个规则有一些例外，但在我们的测试生涯的这个阶段，例外不如规则重要。

### 我们写完测试后可以更改测试吗？

有一天，我们需要改变应用程序类方法的现有行为。在这些情况下，修改相关的测试以适应新行为是可以的。但是，当我们这样做时，我们必须确保运行整个测试套件，而不仅仅是该应用程序类的测试。运行整个测试套件将帮助我们确保更改不会破坏其他类的行为。

### 我们需要测试第三方库吗？

如果我们的遗留应用程序使用第三方库，它们可能已经附带了测试。我们应该不时地运行这些测试。

如果第三方库没有附带测试，我们可能会根据我们的优先级选择编写一些测试。如果我们依赖于库在升级之间表现相同，编写一些我们自己的测试来确保预期的行为保持不变是明智的。

为第三方库构建测试可能很困难，如果它没有以易于测试的方式编写。如果该库是自由软件或开源软件，也许这是一个为项目做出贡献的机会。然而，我们的主要优先事项可能是我们自己的遗留应用程序，而不是第三方库。

### 代码覆盖率呢？

代码覆盖率是 PHPUnit 提供的报告，告诉我们测试了多少行代码。（严格来说，它告诉我们测试了多少语句）。

特定情况可能只测试类的一部分，或者方法的一部分，并留下一些未经测试的代码。被测试的部分称为代码的覆盖部分，而未经测试的部分称为未覆盖部分。

我们主要需要担心的是代码库中未覆盖的部分。如果未覆盖的代码发生任何变化，测试将无法检测到，因此我们可能会面临错误和其他退化。

如果可以的话，我们应该尽早并经常发现我们测试的代码覆盖率。这些覆盖率报告将帮助我们确定下一步需要测试什么，以及代码库的哪些部分需要重构，以便更容易测试。

更多的代码覆盖率是更好的。然而，达到 100%的行覆盖率可能是不可行的（而且实际上也不是最终目标，最终目标是 100%的条件/决策覆盖率等）。不过，如果我们能够达到 100%的覆盖率，那就应该努力去做。

关于这个话题的更多信息，请查阅 PHPUnit 关于代码覆盖率的文档[`phpunit.de/manual/3.7/en/code-coverage-analysis.html`](https://phpunit.de/manual/3.7/en/code-coverage-analysis.html)。

# 回顾和下一步

当我们完成了本章中简要概述的测试编写时，我们将为未来的错误创建了一个很好的陷阱。每当我们运行测试时，对预期行为的任何更改都会作为失败突出，以便我们进行更正。这确保了在我们继续重构时，我们对整个旧代码库所做的贡献将比伤害更多。

此外，因为我们现在有了一个可用的测试套件，我们可以为从旧代码库中提取出的任何新行为添加测试到我们的应用程序类中。每当我们创建一个新的应用程序类方法时，我们也会为该方法创建一个通过的测试。每当我们修改一个应用程序类方法时，我们将运行测试套件，以便在它们进入生产环境之前找到错误和破坏。当我们的测试通过时，我们会感到高兴，当它们失败时，我们也会感到高兴；每一种结果对于现代化我们的旧应用程序来说都是一个积极的迹象。

有了这个，我们可以继续我们的现代化进程。下一步是将数据检索和持久化行为从页面脚本中提取出来，放入一系列类中。通常，这意味着将所有的 SQL 调用移动到一个单独的层中。


# 第八章：将 SQL 语句提取到网关

现在我们已经将所有基于类的功能移动到一个中央目录位置（并且对这些类有一个合理的测试套件），我们可以开始从我们的页面脚本中提取更多的逻辑并将该逻辑放入类中。这将有两个好处：首先，我们将能够保持应用程序的各种关注点分开；其次，我们将能够测试提取的逻辑，以便在部署到生产环境之前很容易注意到任何故障。

这些提取中的第一个将是将所有与 SQL 相关的代码移动到自己的一组类中。对于我们的目的，SQL 是任何读取和写入数据存储系统的代名词。这可能是一个无 SQL 系统，一个 CSV 文件，一个远程资源或其他任何东西。我们将在本章集中讨论 SQL 导向的数据存储，因为它们在遗留应用程序中是如此普遍，但这些原则适用于任何形式的数据存储。

# 嵌入式 SQL 语句

目前，我们的页面脚本（可能还有一些我们的类）直接与数据库交互，使用嵌入式 SQL 语句。例如，一个页面脚本可能有一些类似以下的逻辑：

```php
**page_script.php**
1 <?php
2 $db = new Db($db_host, $db_user, $db_pass);
3 $post_id = $_GET['post_id'];
4 $stm = "SELECT * FROM comments WHERE post_id = $post_id";
5 $rows = $db->query($stm);
6 foreach ($rows as $row) {
7 // output each row
8 }
9 ?>
```

使用嵌入式 SQL 字符串的问题很多。除其他事项外，我们希望：

+   在与代码的其余部分隔离的情况下测试 SQL 交互

+   减少代码库中重复的 SQL 字符串数量

+   收集相关的 SQL 命令以进行概括和重用

+   隔离并消除诸如 SQL 注入之类的安全漏洞

这些问题和更多问题使我们得出结论，我们需要将所有与 SQL 相关的代码提取到一个 SQL 层，并用对我们的 SQL 相关类方法的调用替换嵌入式 SQL 逻辑。我们将通过创建一系列“网关”类来实现这一点。这些“网关”类唯一要做的事情就是从我们的数据源获取数据，并将数据发送回去。

本章中的“网关”类在技术上更像是表数据网关。然而，您可以选择设置适合您数据源的任何类型的“网关”。

## 提取过程

一般来说，这是我们将要遵循的过程：

1.  搜索整个代码库以查找 SQL 语句。

1.  对于每个尚未在“网关”中的语句，将语句和相关逻辑移动到相关的“网关”类方法中。

1.  为新的“网关”方法编写测试。

1.  用“网关”类方法的调用替换原始文件中的语句和相关逻辑。

1.  测试、提交、推送并通知 QA。

1.  重复上述步骤，直到下一个 SQL 语句不在“网关”类之外。

## 搜索 SQL 语句

与前几章一样，在这里我们使用项目范围的搜索功能。使用类似以下的正则表达式来识别代码库中 SQL 语句关键字的位置：

搜索：

```php
**(SELECT|INSERT|UPDATE|DELETE)**

```

我们可能会发现我们的代码库还使用其他 SQL 命令。如果是这样，我们应该将它们包括在搜索表达式中。

如果代码库在 SQL 关键字的大小写方面不一致，对我们来说更容易的是代码库始终只使用一个大小写，无论是大写还是小写。然而，这在遗留代码中并不总是约定俗成的。如果我们的代码库在 SQL 关键字的大小写方面不一致，并且我们的项目范围搜索工具有不区分大小写的选项，我们应该在这次搜索中使用该选项。否则，我们需要扩展搜索项，以包括 SQL 关键字的小写（也许是混合大小写）变体。

最后，搜索结果可能会包括误报。例如，叙述文本如“选择以下选项之一”将出现在结果列表中。我们需要逐个检查结果，以确定它们是否是 SQL 语句还是仅仅是叙述文本。

### 将 SQL 移动到网关类

将 SQL 提取到“网关”的任务是细节导向的，具体情况具体分析。遗留代码库本身的结构将决定这项任务的一个或多个正确方法。

首先，提取一个普通的 SQL 语句如下似乎很简单：

```php
1 <?php
2 $stm = "SELECT * FROM comments WHERE post_id = $post_id";
3 $rows = $db->query($stm);
4 ?>
```

但事实证明，即使在这个简单的例子中，我们也需要做出很多决定：

+   我们应该如何命名`Gateway`类和方法？

+   我们应该如何处理查询的参数？

+   我们如何避免安全漏洞？

+   适当的返回值是什么？

### 命名空间和类名

为了确定我们的命名空间和类名，我们需要首先决定是按层还是按实体进行组织。

+   如果我们按照实现层进行组织，我们类的顶层命名空间可能是`Gateway`或`DataSource\Gateway`。这种命名安排将根据代码库中的操作目的来结构化类。

+   如果我们按领域实体进行组织，顶层命名空间可能是`Comments`，甚至是`Domain\Comments`。这种命名安排将根据业务逻辑领域内的目的来结构化类。

遗留的代码库很可能会决定前进的方向。如果已经有按照某种方式组织的代码，那么最好继续使用已建立的结构，而不是重新做现有的工作。我们希望避免在代码库中设置冲突或不一致的组织结构。

在这两者之间，我建议按领域实体进行组织。我认为将与特定领域实体类型相关的功能集中在其相关的命名空间内更有意义，而不是将操作实现分散在几个命名空间中。我们还可以在特定领域功能内进一步分隔实现部分，这在按层进行组织时不容易做到。

为了反映我的领域实体偏见，本章其余部分的示例将按照领域的方式进行结构化，而不是按照实现层进行结构化。

一旦我们为我们的`Gateway`类确定了一个组织原则，我们就可以很容易地找到好的类名。例如，我们在 PHP 5.3 及更高版本中与评论相关的`Gateway`可能被命名为`Domain\Comments\CommentsGateway`。如果我们使用的是 PHP 5.2 或更早版本，我们将需要避免使用正确的命名空间，并在类名中使用下划线；例如，`Domain_Comments_CommentsGateway`。

### 方法名

然而，选择适当的方法名可能会更加困难。再次，我们应该寻找现有遗留代码库中的惯例。常见的习语可能是`get()`数据，`find()`数据，`fetch()`数据，`select()`数据，或者完全不同的其他内容。

我们应该尽可能坚持任何现有的命名约定。虽然方法名本身并不重要，但命名的一致性很重要。一致性将使我们更容易查看对`Gateway`对象的调用，并理解发生了什么，而无需阅读底层方法代码，并在代码库中搜索数据访问调用。

如果我们的遗留代码库没有显示出一致的模式，那么我们就需要为新的`Gateway`方法选择一致的命名约定。因为`Gateway`类应该是一个简单的层，用于包装 SQL 调用，本章的示例将使用诸如`select`、`insert`等方法名来标识被包装的行为。

最后，方法名可能应该指示正在执行的`select()`的类型。我们是选择一个记录还是所有记录？我们是按特定标准选择？查询中还有其他考虑吗？这些和其他问题将给我们一些提示，告诉我们如何命名`Gateway`方法。

## 一个初始的 Gateway 类方法

在将逻辑提取到类方法时，我们应该小心遵循我们在之前章节中学到的关于依赖注入的所有教训。除其他事项外，这意味着：不使用全局变量，用`Request`对象替换超全局变量，不在`Factory`类之外使用`new`关键字，以及（当然）根据需要通过构造函数注入对象。

根据上述命名原则和原始的`SELECT`语句来检索评论行，我们可以构建一个类似于这样的`Gateway`：

```php
**classes/Domain/Comments/CommentsGateway.php**
1 <?php
2 namespace Domain\Comments;
3
4 class CommentsGateway
5 {
6 protected $db;
7
8 public function __construct(Db $db)
9 {
10 $this->db = $db;
11 }
12
13 public function selectAllByPostId($post_id)
14 {
15 $stm = "SELECT * FROM comments WHERE post_id = {$post_id}";
16 return $this->db->query($stm);
17 }
18 }
19 ?>
```

这实际上是原始页面脚本的逻辑的几乎完全复制。但是，它至少留下了一个主要问题：它直接在查询中使用输入参数。这使我们容易受到 SQL 注入攻击。

### 注意

**什么是 SQL 注入**

关于小鲍比表的经典 XKCD 漫画应该有助于说明问题。恶意形成的输入参数直接用于数据库查询，以更改查询，从而损害或利用数据库。

### 击败 SQL 注入

当我们创建我们的`Gateway`方法时，我们不应假设参数值是安全的。无论我们是否期望参数在每次调用时都被硬编码为常量值，或者以其他方式保证是安全的。在某个时候，有人会更改调用`Gateway`方法的代码的一部分，我们将会有安全问题。相反，我们需要将每个参数值视为不安全，并相应处理。

因此，为了击败 SQL 注入尝试，我们应该在我们的`Gateway`方法中执行每个查询的三件事中的一件（实际上，在代码库中的任何 SQL 语句中）：

1.  最好的解决方案是使用准备语句和参数绑定，而不是查询字符串插值。

1.  第二好的解决方案是在将其插入查询字符串之前，对每个参数使用数据库层的“引用和转义”机制。

1.  第三好的解决方案是在将其插入查询字符串之前转义每个输入参数。

### 提示

或者，我们可以通过将预期的数值转换为`int`或`float`来完全避免字符串的问题。

让我们首先检查第三好的解决方案，因为它更有可能已经存在于我们的遗留代码库中。我们使用数据库的`escape`功能来转义每个参数，然后在查询字符串中使用它，并为数据库适当地引用它。因此，我们可以像这样重写`selectAllByPostId()`方法，假设使用 MySQL 数据库：

```php
<?php
2 public function selectAllByPostId($post_id)
3 {
4 $post_id = "'" . $this->db->escape($post_id) . "'";
5 $stm = "SELECT * FROM comments WHERE post_id = {$post_id}";
6 return $this->db->query($stm);
7 }
8 ?>
```

对值进行转义以插入字符串是第三好的解决方案，原因有几个。主要原因是转义逻辑有时不够。像`mysql_escape_string()`函数对我们的目的来说根本不够好。甚至`mysql_real_escape_string()`方法也有一个缺陷，这将允许攻击者根据当前字符集成功进行 SQL 注入尝试。然而，这可能是底层数据库驱动程序可用的唯一选项。

第二好的解决方案是一种称为引用和转义的转义的变体。这个功能只能通过`PDO::quote()`方法使用，比转义更安全，因为它还会自动将值包装在引号中，并处理适当的字符集。这避免了仅仅转义和自己添加引号时固有的字符集不匹配问题。

一个重写的`selectAllByPostId()`方法可能看起来像这样，使用暴露`PDO::quote()`方法的`Db`对象：

```php
<?php
2 public function selectAllByPostId($post_id)
3 {
4 $post_id = $this->db->quote($post_id);
5 $stm = "SELECT * FROM comments WHERE post_id = {$post_id}";
6 return $this->db->query($stm);
7 }
8 ?>
```

当我们记得使用它时，这是一种安全的方法。当然，问题在于，如果我们向方法添加参数，可能会忘记引用它，然后我们又容易受到 SQL 注入攻击。

最后，最好的解决方案：准备语句和参数绑定。这些只能通过 PDO（几乎适用于所有数据库）和`mysqli`扩展使用。每个都有自己的处理语句准备的变体。我们将在这里使用`PDO`样式的示例。

我们使用命名占位符而不是将值插入查询字符串，以指示参数应放置在查询字符串中的位置。然后，我们告诉`PDO`将字符串准备为`PDOStatement`对象，并在通过准备的语句执行查询时将值绑定到命名占位符。`PDO`自动使用参数值的安全表示，使我们免受 SQL 注入攻击。

以下是使用公开`PDO`语句准备逻辑和执行的`Db`对象进行重写的示例：

```php
1 <?php
2 public function selectAllByPostId($post_id)
3 {
4 $stm = "SELECT * FROM comments WHERE post_id = :post_id";
5 $bind = array('post_id' => $post_id);
6
7 $sth = $this->db->prepare($stm);
8 $sth->execute($bind);
9 return $sth->fetchAll(PDO::FETCH_ASSOC);
10 }
11 ?>
```

这里的巨大好处是我们从不在查询字符串中使用参数变量。我们总是只使用命名占位符，并将占位符绑定到准备好的语句中的参数值。这种习惯用法使我们清楚地知道何时不正确地使用了插入的变量，而且`PDO`会自动投诉如果有额外或缺少的绑定值，因此意外进行不安全的更改的机会大大减少了。

### 编写一个测试

现在是时候为我们的新类方法编写测试了。我们此时编写的测试可能不够完美，因为我们需要与数据库交互。然而，一个不完美的测试总比没有测试好。正如《测试之道》所告诉我们的，我们在能够的时候编写测试。

我们的新`Gateway`方法的测试可能看起来像这样：

```php
**tests/classes/Domain/Comments/CommentsGatewayTest.php**
1 <?php
2 namespace Domain\Comments;
3
4 use Db;
5
6 class CommentsGatewayTest
7 {
8 protected $db;
9
10 protected $gateway;
11
12 public function setUp()
13 {
14 $this->db = new Db('test_host', 'test_user', 'test_pass');
15 $this->gateway = new CommentsGateway($this->db);
16 }
17
18 public function testSelectAllByPostId()
19 {
20 // a range of known IDs in the comments table
21 $post_id = mt_rand(1,100);
22
23 // get the comment rows
24 $rows = $this->gateway->selectAllByPostId($post_id);
25
26 // make sure they all match the post_id
27 foreach ($rows as $row) {
28 $this->assertEquals($post_id, $row['post_id']);
29 }
30 }
31 }
32 ?>
```

现在我们运行我们的测试套件，看看测试是否通过。如果通过，我们会庆祝并继续前进！如果没有通过，我们将继续完善`Gateway`方法和相关测试，直到两者都正常工作。

### 提示

**完善我们的测试**

正如前面所述，这是一个非常不完美的测试。除其他事项外，它取决于一个可用的数据库连接，并且首先需要在数据库中种子数据。通过依赖数据库，我们依赖它处于正确的状态。如果数据库中没有正确的数据，那么测试将失败。失败不是来自我们正在测试的代码，而是来自大部分超出我们控制的数据库。改进测试的一个机会是将`Gateway`类更改为依赖于`DbInterface`而不是具体的`Db`类。然后，我们将为测试目的创建一个实现`DbInterface`的`FakeDb`类，并将一个`FakeDb`实例注入到`Gateway`中，而不是一个真正的`Db`实例。这样做将使我们更深入地了解 SQL 查询字符串的正确性，以及对返回给`Gateway`的数据具有更大的控制。最重要的是，它将使测试与对可用数据库的依赖解耦。目前，出于迅速进行的考虑，我们将使用不完美的测试。

### 替换原始代码

现在我们有一个可工作且经过测试的`Gateway`方法，我们用调用`Gateway`方法替换原始代码。而旧代码看起来像这样：

```php
**page_script.php (before)**
1 <?php
2 $db = new Db($db_host, $db_user, $db_pass);
3 $post_id = $_GET['post_id'];
4 $stm = "SELECT * FROM comments WHERE post_id = $post_id";
5 $rows = $db->query($stm);
6 foreach ($rows as $row) {
7 // output each row
8 }
9 ?>
```

新版本将如下所示：

```php
**page_script.php (after)**
1 <?php
2 $db = new Db($db_host, $db_user, $db_pass);
3 $comments_gateway = new CommentsGateway($db);
4 $rows = $comments_gateway->selectAllByPostId($_GET['post_id']);
5 foreach ($rows as $row) {\
6 // output each row
7 }
8 ?>
```

请注意，我们几乎没有修改操作逻辑。例如，我们没有添加以前不存在的错误检查。我们修改的最远程度是通过准备好的语句来保护查询免受 SQL 注入。

### 测试，提交，推送，通知 QA

与之前的章节一样，现在我们需要抽查旧应用程序。虽然我们对新的`Gateway`方法有一个单元测试，但我们仍然需要抽查我们修改过的应用程序的部分。如果我们之前准备了一个表征测试来覆盖我们遗留应用程序的这一部分，我们现在可以运行它。否则，我们可以通过浏览或以其他方式调用应用程序的更改部分来进行此操作。

一旦我们确信已成功用调用我们的新`Gateway`方法替换了嵌入式 SQL，我们就将更改提交到版本控制，包括我们的测试。然后我们推送到中央仓库，并通知 QA 团队我们的更改。

### 做...直到

完成后，我们再次搜索代码库，查找 SQL 关键字以指示嵌入式查询字符串的用法。如果它们存在于`Gateway`类之外，我们将继续将查询提取到适当的`Gateway`中。一旦所有 SQL 语句都已移动到`Gateway`类中，我们就完成了。

## 常见问题

### 那么插入、更新和删除语句呢？

到目前为止，我们只看了`SELECT`语句，因为它们很可能是我们传统代码库中最常见的情况。然而，还会有大量的`INSERT`，`UPDATE`，`DELETE`，以及其他语句。在提取到`Gateway`时，这些基本上与`SELECT`相同，但也有一些细微的差异。

特别是`INSERT`和`UPDATE`语句可能包含大量的参数，指示要插入或更新的列值。将太多的参数添加到提取的`Gateway`方法签名中将使其难以处理。

在这些情况下，我们可以使用数据数组来指示列名及其对应的值。但我们需要确保只插入或更新正确的列。

例如，假设我们从页面脚本中开始，保存一个新的评论，包括评论者的姓名、评论内容、评论者的 IP 地址以及评论所附加的帖子 ID：

```php
**page_script.php**
1 <?php
2 $db = new Db($db_host, $db_user, $db_pass);
3
4 $name = $db->escape($_POST['name']);
5 $body = $db->escape($_POST['body']);
6 $post_id = (int) $_POST['id'];
7 $ip = $db->escape($_SERVER['REMOTE_ADDR']);
8
9 $stm = "INSERT INTO comments (post_id, name, body, ip) "
10 .= "VALUES ($post_id, '{$name}', '{$body}', '{$ip}'";
11
12 $db->query($stm);
13 $comment_id = $db->lastInsertId();
14 ?>
```

当我们将这些提取到`CommentsGateway`中的方法时，我们可以为每个要插入的列值设置一个参数。在这种情况下，只有四列，但如果有十几列，方法签名将更难处理。

作为每列一个参数的替代方案，我们可以将数据数组作为单个参数传递，然后在方法内部处理。这个使用数据数组的示例包括一个带有占位符的预处理语句，以防止 SQL 注入攻击：

```php
1 <?php
2 public function insert(array $bind)
3 {
4 $stm = "INSERT INTO comments (post_id, name, body, ip) "
5 .= "VALUES (:post_id, :name, :body, :ip)";
6 $this->db->query($stm, $bind);
7 return $this->db->lastInsertId();
8 }
9 ?>
```

一旦我们在`CommentsGateway`中有了这样的方法，我们可以修改原始代码，使其更像下面这样：

```php
**page_script.php**
1 <?php
2 $db = new Db($db_host, $db_user, $db_pass);
3 $comments_gateway = new CommentsGateway($db);
4
5 $input = array(
6 'name' => $_POST['name'],
7 'body' => $_POST['body'],
8 'post_id' => $_POST['id'],
9 'ip' => $_SERVER['REMOTE_ADDR'],
10 );
11
12 $comment_id = $comments_gateway->insert($input);
13 ?>
```

### 重复的 SQL 字符串怎么办？

在这个过程中，我们可能会遇到的一件事是，在我们的传统应用程序中，查询字符串中存在大量的重复，或者是带有变化的重复。

例如，我们可能会在传统应用程序的其他地方找到一个类似于这样的与评论相关的查询：

```php
1 <?php
2 $stm = "SELECT * FROM comments WHERE post_id = $post_id LIMIT 10";
3 ?>
```

查询字符串与本章开头的示例代码相同，只是附加了一个`LIMIT`子句。我们应该为这个查询创建一个全新的方法，还是修改现有的方法？

这是需要专业判断和对代码库的熟悉。在这种情况下，修改似乎是合理的，但在其他情况下，差异可能足够大，需要创建一个全新的方法。

如果我们选择修改`CommentsGateway`中的现有方法，我们可以重写`selectAllByPostId()`以包括一个可选的`LIMIT`：

```php
1 <?php
2 public function selectAllByPostId($post_id, $limit = null)
3 {
4 $stm = "SELECT * FROM comments WHERE post_id = :post_id";
5 if ($limit) {
6 $stm .= " LIMIT " . (int) $limit;
7 }
8 $bind = array('post_id' => $post_id);
9 return $this->db->query($stm, $bind);
10 }
11 ?>
```

现在我们已经修改了应用程序类，我们需要运行现有的测试。如果测试失败，那我们就庆幸！我们发现了我们的改变有缺陷，而测试阻止了这个 bug 进入生产。如果测试通过，我们也庆幸，因为事情仍然像改变之前一样工作。

最后，在现有测试通过后，我们修改`CommentsGatewayTest`，以检查新的`LIMIT`功能是否正常工作。这个测试仍然不完美，但它传达了要点。

```php
tests/classes/Domain/Comments/CommentsGatewayTest.php
1 <?php
2 public function testSelectAllByPostId()
3 {
4 // a range of known IDs in the comments table
5 $post_id = mt_rand(1,100);
6
7 // get the comment rows
8 $rows = $this->gateway->selectAllByPostId($post_id);
9
10 // make sure they all match the post_id
11 foreach ($rows as $row) {
12 $this->assertEquals($post_id, $row['post_id']);
13 }
14
15 // test with a limit
16 $limit = 10;
17 $rows = $this->gateway->selectAllByPostId($post_id, $limit);
18 $this->assertTrue(count($rows) <= $limit);
19 }
20 }
21 ?>
```

我们再次运行测试，以确保我们的新的`LIMIT`功能正常工作，并不断完善代码和测试，直到通过为止。

然后我们继续用`Gateway`的调用替换原始的嵌入式 SQL 代码，进行抽查，提交等等。

### 注意

我们需要谨慎处理。在看到一个查询的变体之后，我们将能够想象出许多其他可能的查询变体。由此产生的诱惑是在实际遇到这些变体之前，就预先修改我们的`Gateway`方法来适应想象中的变体。除非我们实际在遗留代码库中看到了特定的变体，否则我们应该克制自己，不要为那种变体编写代码。我们不希望超前于代码库当前实际需要的情况。目标是在可见的路径上小步改进，而不是在想象的迷雾中大步跨越。

### 复杂的查询字符串怎么办？

到目前为止，示例都是相对简单的查询字符串。这些简单的示例有助于保持流程清晰。然而，在我们的遗留代码库中，我们可能会看到非常复杂的查询。这些查询可能是由多个条件语句构建而成，使用多个不同的参数在查询中使用。以下是一个复杂查询的示例，摘自附录 A，*典型的遗留页面脚本*：

```php
1 <?php
2 // ...
3 define("SEARCHNUM", 10);
4 // ...
5 $page = ($page) ? $page : 0;
6
7 if (!empty($p) && $p!="all" && $p!="none") {
8 $where = "`foo` LIKE '%$p%'";
9 } else {
10 $where = "1";
11 }
12
13 if ($p=="hand") {
14 $where = "`foo` LIKE '%type1%'"
15 . " OR `foo` LIKE '%type2%'"
16 . " OR `foo` LIKE '%type3%'";
17 }
18
19 $where .= " AND `bar`='1'";
20 if ($s) {
21 $s = str_replace(" ", "%", $s);
22 $s = str_replace("'", "", $s);
23 $s = str_replace(";", "", $s);
24 $where .= " AND (`baz` LIKE '%$s%')";
25 $orderby = "ORDER BY `baz` ASC";
26 } elseif ($letter!="none" && $letter) {
27 $where .= " AND (`baz` LIKE '$letter%'"
28 . " OR `baz` LIKE 'The $letter%')";
29 $orderby = "ORDER BY `baz` ASC";
30 } else {
31 $orderby = "ORDER BY `item_date` DESC";
32 }
33 $query = mysql_query(
34 "SELECT * FROM `items` WHERE $where $orderby
35 LIMIT $page,".SEARCHNUM;
36 );
37 ?>
```

对于这种复杂的安排，我们需要非常注意细节，将相关的查询构建逻辑提取到我们的`Gateway`中。主要考虑因素是确定查询构建逻辑中使用了哪些变量，并将其设置为我们新的`Gateway`方法的参数。然后我们可以将查询构建逻辑移动到我们的`Gateway`中。

首先，我们可以尝试将嵌入的与 SQL 相关的逻辑提取到`Gateway`方法中：

```php
1 <?php
2 namespace Domain\Items;
3
4 class ItemsGateway
5 {
6 protected $mysql_link;
7
8 public function __construct($mysql_link)
9 {
10 $this->mysql_link = $mysql_link;
11 }
12
13 public function selectAll(
14 $p = null,
15 $s = null,
16 $letter = null,
17 $page = 0,
18 $searchnum = 10
19 ) {
20 if (!empty($p) && $p!="all" && $p!="none") {
21 $where = "`foo` LIKE '%$p%'";
22 } else {
23 $where = "1";
24 }
25
26 if ($p=="hand") {
Extract SQL Statements To Gateways 84
27 $where = "`foo` LIKE '%type1%'"
28 . " OR `foo` LIKE '%type2%'"
29 . " OR `foo` LIKE '%type3%'";
30 }
31
32 $where .= " AND `bar`='1'";
33 if ($s) {
34 $s = str_replace(" ", "%", $s);
35 $s = str_replace("'", "", $s);
36 $s = str_replace(";", "", $s);
37 $where .= " AND (`baz` LIKE '%$s%')";
38 $orderby = "ORDER BY `baz` ASC";
39 } elseif ($letter!="none" && $letter) {
40 $where .= " AND (`baz` LIKE '$letter%'"
41 . " OR `baz` LIKE 'The $letter%')";
42 $orderby = "ORDER BY `baz` ASC";
43 } else {
44 $orderby = "ORDER BY `item_date` DESC";
45 }
46
47 $stm = "SELECT *
48 FROM `items`
49 WHERE $where
50 $orderby
51 LIMIT $page, $searchnum";
52
53 return mysql_query($stm, $this->mysql_link);
54 }
55 }
56 ?>
```

### 注意

尽管我们已经删除了一些依赖项（例如对`mysql_connect()`链接标识符的隐式全局依赖），但这第一次尝试仍然存在许多问题。其中，它仍然容易受到 SQL 注入的影响。我们需要在查询中使用`mysql_real_escape_string()`对每个参数进行转义，并将`LIMIT`值转换为整数。

一旦我们完成了提取及其相关的测试，我们将把原始代码更改为以下内容：

```php
1 <?php
2 // ...
3 define("SEARCHNUM", 10);
4 // ...
5 $page = ($page) ? $page : 0;
6 $mysql_link = mysql_connect($db_host, $db_user, $db_pass);
7 $items_gateway = new \Domain\Items\ItemsGateway($mysql_link);
8 $query = $items_gateway->selectAll($p, $s, $letter, $page, SEARCHNUM);
9 ?>
```

### 非 Gateway 类内的查询怎么办？

本章的示例显示了嵌入在页面脚本中的 SQL 查询字符串。同样可能的是，我们也会在非 Gateway 类中找到嵌入的查询字符串。

在这些情况下，我们遵循与页面脚本相同的流程。一个额外的问题是，我们将不得不将`Gateway`依赖项传递给该类。例如，假设我们有一个`Foo`类，它使用`doSomething()`方法来检索评论：

```php
1 <?php
2 class Foo
3 {
4 protected $db;
5
6 public function __construct(Db $db)
7 {
8 $this->db = $db;
9 }
10
11 public function doSomething($post_id)
12 {
13 $stm = "SELECT * FROM comments WHERE post_id = $post_id";
14 $rows = $this->db->query($stm);
15 foreach ($rows as $row) {
16 // do something with each row
17 }
18 return $rows;
19 }
20 }
21 ?>
```

我们提取 SQL 查询字符串及其相关逻辑，就像我们在页面脚本中所做的那样。然后我们修改`Foo`类，将`Gateway`作为依赖项，而不是`Db`对象，并根据需要使用`Gateway`：

```php
1 <?php
2 use Domain\Comments\CommentsGateway;
3
4 class Foo
5 {
6 protected $comments_gateway;
7
8 public function __construct(CommentsGateway $comments_gateway)
9 {
10 $this->comments_gateway = $comments_gateway;
11 }
12
13 public function doSomething($post_id)
14 {
15 $rows = $this->comments_gateway->selectAllByPostId($post_id);
16 foreach ($rows as $row) {
17 // do something with each row
18 }
19 return $rows;
20 }
21 }
22 ?>
```

### 我们可以从基类 Gateway 类扩展吗？

如果我们有许多具有类似功能的`Gateway`类，将一些功能收集到`AbstractGateway`中可能是合理的。例如，如果它们都需要`Db`连接，并且都有类似的`select*()`方法，我们可以做如下操作：

```php
classes/AbstractGateway.php
1 <?php
2 abstract class AbstractGateway
3 {
4 protected $table;
5
6 protected $primary_key;
7
8 public function __construct(Db $db)
9 {
10 $this->db = $db;
11 }
12
13 public function selectOneByPrimaryKey($primary_val)
14 {
15 $stm = "SELECT * FROM {$this->table} "
16 .= "WHERE {$this->primary_key} = :primary_val";
17 $bind = array('primary_val' => $primary_val);
18 return $this->db->query($stm, $bind);
19 }
20 }
21 ?>
```

然后我们可以从基类`AbstractGateway`扩展一个类，并调整特定表的扩展属性：

```php
1 <?php
2 namespace Domain\Items;
3
4 class ItemsGateway extends \AbstractGateway
5 {
6 protected $table = 'items';
7 protected $primary_key = 'item_id';
8 }
9 ?>
```

基本的`selectOneByPrimaryKey()`方法可以与各种`Gateway`类一起使用。根据需要，我们仍然可以在特定的`Gateway`类上添加其他具体的方法。

### 注意

对于这种方法要谨慎。我们应该只抽象出已经存在于我们已经提取的行为中的功能。抵制提前创建我们在遗留代码库中实际上还没有看到的功能的诱惑。

### 多个查询和复杂的结果结构怎么办？

本章中的示例已经显示了针对单个表的单个查询。我们可能会遇到使用多个查询针对几个不同的表，然后将结果合并为复杂领域实体或集合的逻辑。以下是一个例子：

```php
1 <?php
2 // build a structure of posts with author and statistics data,
3 // with all comments on each post.
4 $page = (int) $_GET['page'];
5 $limit = 10;
6 $offset = $page * $limit; // a zero-based paging system
7 $stm = "SELECT *
8 FROM posts
9 LEFT JOIN authors ON authors.id = posts.author_id
10 LEFT JOIN stats ON stats.post_id = posts.id
11 LIMIT {$limit} OFFSET {$offset}"
12 $posts = $db->query($stm);
13
14 foreach ($posts as &$post) {
15 $stm = "SELECT * FROM comments WHERE post_id = {$post['id']}";
16 $post['comments'] = $db->query($stm);
17 }
18 ?>
```

### 注意

这个例子展示了一个经典的 N+1 问题，其中为主集合的每个成员发出一个查询。获取博客文章的第一个查询将跟随 10 个查询，每个博客文章一个，以获取评论。因此，总查询数为 10，加上初始查询为 1。对于 50 篇文章，总共将有 51 个查询。这是遗留应用程序中性能拖慢的典型原因。有关 N+1 问题的详细讨论和解决方案，请参见*Solving The N+1 Problem in PHP* ([`leanpub.com/sn1php`](https://leanpub.com/sn1php))

第一个问题是确定如何将查询拆分为`Gateway`方法。有些查询必须一起进行，而其他查询可以分开。在这种情况下，第一个和第二个查询可以分开到不同的`Gateway`类和方法中。

下一个问题是确定哪个`Gateway`类应接收提取的逻辑。当涉及多个表时，有时很难确定，因此我们必须选择查询的主要主题。上面的第一个查询涉及到文章、作者和统计数据，但从逻辑上看，我们主要关注的是文章。

因此，我们可以将第一个查询提取到`PostsGateway`中。我们希望尽可能少地修改查询本身，因此我们保留连接和其他内容不变：

```php
1 <?php
2 namespace Domain\Posts;
3
4 class PostsGateway
5 {
6 protected $db;
7
8 public function __construct(Db $db)
9 {
10 $this->db = $db;
11 }
12
13 public function selectAllWithAuthorsAndStats($limit = null, $offset = null)
14 {
15 $limit = (int) $limit;
https://leanpub.com/sn1php
16 $offset = (int) $offset;
17 $stm = "SELECT *
18 FROM posts
19 LEFT JOIN authors ON authors.id = posts.author_id
20 LEFT JOIN stats ON stats.post_id = posts.id
21 LIMIT {$limit} OFFSET {$offset}"
22 return $this->db->query($stm);
23 }
24 }
25 ?>
```

完成后，我们继续根据第一个查询编写新功能的测试。我们修改代码并进行测试，直到测试通过。

第二个查询，与评论相关的查询，与我们之前的例子相同。

在完成提取及其相关测试后，我们可以修改页面脚本，使其如下所示：

```php
1 <?php
2 $db = new Database($db_host, $db_user, $db_pass);
3 $posts_gateway = new \Domain\Posts\PostsGateway($db);
4 $comments_gateway = new \Domain\Comments\CommentsGateway($db);
5
6 // build a structure of posts with author and statistics data,
7 // with all comments on each post.
8 $page = (int) $_GET['page'];
9 $limit = 10;
10 $offset = $page * $limit; // a zero-based paging system
11 $posts = $posts_gateway->selectAllWithAuthorsAndStats($limit, $offset);
12
13 foreach ($posts as &$post) {
14 $post['comments'] = $comments_gateway->selectAllByPostId($post['id']);
15 }
16 ?>
```

### 如果没有数据库类会怎么样？

许多遗留代码库没有数据库访问层。相反，这些遗留应用程序直接在其页面脚本中使用`mysql`扩展。对`mysql`函数的调用分散在整个代码库中，并未收集到单个类中。

如果我们可以升级到`PDO`，我们应该这样做。然而，由于各种原因，可能无法从`mysql`升级。`PDO`的工作方式与`mysql`不完全相同，从`mysql`习语更改为`PDO`习语可能一次性做得太多。此时进行迁移可能会使测试变得比我们想要的更加困难。

另一方面，我们可以将`mysql`调用按原样移入我们的`Gateway`类中。起初这样做似乎是合理的。然而，`mysql`扩展内置了一些全局状态。任何需要链接标识符（即服务器连接）的`mysql`函数在没有传递链接标识符时会自动使用最近的连接资源。这与依赖注入的原则相违背，因为如果可能的话，我们宁愿不依赖全局状态。

因此，我建议我们不直接迁移到 PDO，也不将`msyql`函数调用保持原样，而是将`mysql`调用封装在一个类中，该类代理方法调用到`mysql`函数。然后，我们可以使用类方法而不是`mysql`函数。类本身可以包含链接标识符，并将其传递给每个方法调用。这将为我们提供一个数据库访问层，我们的`Gateway`对象可以使用，而不会太大地改变`mysql`的习惯用法。

这样一个包装器的一个操作示例实现是`MysqlDatabase`类。当我们创建一个`MysqlDatabase`的实例时，它会保留连接信息，但实际上不会连接到服务器。只有在我们调用实际需要服务器连接的方法时才会连接。这种延迟加载的方法有助于减少资源使用。此外，`MysqlDatabase`类明确添加了链接标识参数，这在相关的`mysql`函数中是可选的，这样我们就不会依赖于`mysql`扩展的隐式全局状态。

要用`MysqlDatabase`调用替换`mysql`函数调用：

1.  在整个代码库中搜索`mysql_`前缀的函数调用。

1.  在每个文件中，如果有带有`mysql_`函数前缀的函数调用...

+   创建或注入一个`MysqlDatabase`的实例。

+   用`MysqlDatabase`对象变量和一个箭头操作符(`->`)替换每个`mysql_`函数前缀。如果我们对风格很挑剔，我们还可以将剩余的方法名部分从`snake_case()`转换为`camelCase()`。

1.  抽查，提交，推送，并通知 QA。

1.  继续搜索`mysql_`前缀的函数调用，直到它们都被替换为`MysqlDatabase`方法调用。

例如，假设我们有这样一个遗留代码：

```php
**Using mysql functions**
1 <?php
2 mysql_connect($db_host, $db_user, $db_pass);
3 mysql_select_db('my_database');
4 $result = mysql_query('SELECT * FROM table_name LIMIT 10');
5 while ($row = mysql_fetch_assoc($result)) {
6 // do something with each row
7 }
8 ?>
```

使用上述过程，我们可以将代码转换为使用`MysqlDatabase`对象：

**使用 MysqlDatabase 类**

```php
1 <?php
2 $db = new \Mlaphp\MysqlDatabase($db_host, $db_user, $db_pass);
3 $db->select_db('my_database'); // or $db->selectDb('my_database')
4 $result = $db->query('SELECT * FROM table_name LIMIT 10');
5 while ($row = $db->fetch_assoc($result)) {
6 // do something with each row
7 }
8 ?>
```

这段代码，反过来可以使用一个注入的`MysqlDatabase`对象提取到一个`Gateway`类中。

### 注意

对于我们的页面脚本，最好在现有的设置文件中创建一个`MysqlDatabase`实例并使用它，而不是在每个页面脚本中单独创建一个。实现的延迟连接性意味着如果我们从未对数据库进行调用，就永远不会建立连接，因此我们不需要担心不必要的资源使用。现有的遗留代码库将帮助我们确定这是否是一个合理的方法。

一旦我们的`Gateway`类使用了一个注入的`MysqlDatabase`对象，我们就可以开始计划从封装的`mysql`函数迁移到具有不同习惯用法和用法的`PDO`。因为数据库访问逻辑现在由`Gateway`对象封装，所以迁移和测试将比如果我们替换了遍布整个代码库的`mysql`调用要容易。

# 审查和下一步

当我们完成了这一步，我们所有的 SQL 语句将在`Gateway`类中，而不再在我们的页面脚本或其他非`Gateway`类中。我们还将对我们的`Gateway`类进行测试。

从现在开始，每当我们需要向数据库添加新的调用时，我们只会在`Gateway`类中这样做。每当我们需要获取或保存数据时，我们将使用`Gateway`方法，而不是编写嵌入式 SQL。这使我们在数据库交互和未来的模型层和实体对象之间有了明确的关注点分离。

现在我们已经将数据库交互分离到了它们自己的层中，我们将检查整个遗留应用程序中对`Gateway`对象的所有调用。我们将检查页面脚本和其他类如何操作返回的结果，并开始提取定义我们模型层的行为。


# 第九章：将域逻辑提取到事务中

在上一章中，我们将所有 SQL 语句提取到了*网关*对象的一层。这样封装了应用程序与数据库之间的交互。

然而，我们通常需要对从数据库获取的数据应用一定数量的业务或域逻辑，以及返回数据库。逻辑可以包括数据验证，添加或修改值以用于演示或计算目的，将更简单的记录收集到更复杂的记录中，使用数据执行相关操作等。这种域逻辑通常嵌入到页面脚本中，使得该逻辑难以重用和测试。

本章描述了将域行为提取到单独层的一种方法。在许多方面，本章构成了本书的核心：到目前为止，一切都导致了我们对遗留应用程序的这一核心关注点，而之后的一切将引导我们进入这个核心功能周围和上面的层。

### 注意

**域还是模型？**

遗留应用程序中的域逻辑是模型-视图-控制器中的模型部分。然而，遗留代码库不太可能有提供业务域的完整模型的单独实体对象。因此，在本章中，我们将讨论域逻辑而不是模型逻辑。如果我们足够幸运已经有了单独的模型对象，那就更好了。

# 嵌入式域逻辑

尽管我们已经提取了 SQL 语句，页面脚本和类可能正在操作结果并执行与检索数据相关的其他操作。这些操作和动作是域逻辑的核心，目前它们与其他非域关注点一起嵌入。

我们可以通过查看附录 B 中的代码，*网关之前的代码*和附录 C 中的代码，*网关之后的代码*，来看到从嵌入式 SQL 到使用*网关*类的进展。这里的代码太长，无法在此处呈现。我们要注意的是，即使在提取嵌入式 SQL 语句之后，代码仍然在将结果呈现给用户之前对传入和传出的数据进行了大量处理。

将域逻辑嵌入页面脚本中使得难以独立测试该逻辑。我们也无法轻松地重用它。如果我们想要搜索在如何处理域实体（在本例中是一系列文章）方面的重复和重复，我们需要审查整个应用程序中的每个页面脚本。

这里的解决方案是将域逻辑提取到一个或多个类中，以便我们可以独立于任何特定页面脚本对它们进行测试。然后我们可以实例化域逻辑类并在任何我们喜欢的页面脚本中使用它们。

在应用该解决方案之前，我们需要确定如何为我们的域逻辑结构目标类。 

## 域逻辑模式

Martin Fowler 的**企业应用架构模式**（**PoEAA**）目录了四种域逻辑模式：

+   **事务脚本**：它主要将[域]逻辑组织为单个过程，直接调用数据库或通过一个薄的数据库包装器。每个事务都将有自己的事务脚本，尽管常见的子任务可以分解为子过程。

+   **域模型**：它创建了一组相互连接的对象，其中每个对象代表一些有意义的个体，无论是像公司那样大，还是像订单表上的一行那样小。

+   **表模块**：它使用数据库中每个表一个类的方式组织域逻辑，并且一个类的单个实例包含将对数据进行操作的各种过程，如果你有很多订单，域模型将每个订单一个订单对象，而表模块将有一个对象来处理所有订单。

+   **服务层**：它从客户端层的接口角度定义了应用程序的边界和可用操作集。它封装了应用程序的业务逻辑，在实现其操作时控制事务并协调响应。

### 注意

我强烈建议购买 PoEAA 的纸质版，并完整阅读模式描述和示例。这本书对专业程序员来说是一个绝对必备的参考书。我发现自己每周都要查阅它（有时更频繁），它总是能提供清晰和洞察力。

现在我们面临的选择是：鉴于我们遗留应用程序的现有结构，哪种模式最适合当前的架构？

在这一点上，我们将放弃服务层，因为它暗示着一个在我们遗留应用程序中可能不存在的复杂程度。同样，我们也将放弃领域模型，因为它暗示着一个封装行为的良好设计的业务实体对象集。如果遗留应用程序已经实现了这些模式中的一个，那就更好了。否则，这就只剩下表模块和交易脚本模式了。

在上一章中，当我们将 SQL 语句提取到`Gateway`类中时，这些`Gateway`类很可能遵循了表数据网关模式，特别是如果它们足够简单，只与每个`Gateway`类交互一个表。这使得表模块模式似乎是我们领域逻辑的一个很好的选择。

然而，剩下的每个页面脚本或嵌入领域逻辑的类可能不太可能一次只与一个表交互。更频繁地，遗留应用程序在一个类或脚本中跨多个表有许多交互。因此，当我们提取领域逻辑时，我们将首先使用交易脚本模式。

交易脚本无可否认是一种简单的模式。通过它，我们将领域逻辑从页面脚本中提取出来，基本完整地转移到一个类方法中。我们只对逻辑进行修改，以便将数据正确地输入和输出到类方法中，以便原始代码仍然能够正常运行。

尽管我们可能希望有比交易脚本更复杂的东西，但我们必须记住，我们在这里的目标之一是尽量避免对现有逻辑进行太大的改变。我们是重构，而不是重写。我们现在想要的是将代码移动到适当的位置，以便进行适当的测试和重用。因此，交易脚本可能是包装我们遗留的领域逻辑的最佳方式，就像它存在的那样，而不是我们希望它成为的样子。

一旦我们将领域逻辑提取到自己的层中，我们就能更清晰地看到这个逻辑，减少干扰。在那时，如果真的需要的话，我们可以开始计划将领域层重构为更复杂的东西。例如，我们可以构建一个使用表模块或领域模型来协调各种领域交互的服务层。服务层向页面脚本呈现的接口可能与交易脚本接口完全保持不变，尽管底层架构可能已经完全改变。但这是另一天的任务。

### 注意

**活动记录呢？**

Ruby on Rails 以使用活动记录模式而闻名，许多 PHP 开发人员喜欢这种数据库交互方式。它确实有其优势。然而，Fowler 将活动记录分类为数据源架构模式，而不是领域逻辑模式，因此我们不会在这里讨论它。

# 提取过程

在本书中描述的重构过程中，提取领域逻辑将是最困难、耗时和细节导向的。这是一件非常艰难的事情，需要非常小心和注意。领域逻辑是我们遗留应用程序的核心，我们需要确保只提取出正确的部分。这意味着成功完全取决于我们对现有遗留应用程序的熟悉程度和能力。

幸运的是，我们之前对现代化遗留代码库的练习已经让我们对整个应用程序有了广泛的了解，以及对我们必须提取和重构的特定部分有了深入的了解。这应该让我们有信心成功完成这项任务。这是一项要求很高，但最终令人满意的活动。

一般来说，我们按照以下步骤进行：

1.  搜索整个代码库，查找存在于“交易”类之外的“网关”类的使用情况。

1.  在发现“网关”使用的地方，检查围绕“网关”操作的逻辑，以发现该逻辑的哪些部分与应用程序的领域行为相关。

1.  提取相关的领域逻辑到一个或多个与领域元素相关的“交易”类中，并修改原始代码以使用“交易”类而不是嵌入的领域逻辑。

1.  抽查以确保原始代码仍然正常工作，并根据需要修改提取的逻辑以确保正确运行。

1.  为提取的“交易”逻辑编写测试，并随着测试代码的完善而完善测试，直到测试通过。

1.  当所有原始测试和新测试都通过时，提交代码和测试，推送到公共存储库，并通知质量保证部门。

1.  再次搜索“网关”类的使用情况，并继续提取领域逻辑，直到“网关”的使用仅存在于“交易”中。

## 搜索“网关”的使用情况

与早期章节一样，我们使用项目范围的搜索功能来查找我们创建“网关”类实例的位置：

搜索：

```php
**new .*Gateway**

```

新的“网关”实例可能直接在页面脚本中使用，这种情况下我们已经找到了一些候选代码来提取领域逻辑。如果“网关”实例被注入到一个类中，我们现在需要深入到该类中找到“网关”的使用位置。围绕该使用的代码将成为我们提取领域逻辑的候选代码。

### 发现和提取相关的领域逻辑

### 提示

在将逻辑提取到类方法时，我们应该小心遵循我们在之前章节中学到的关于依赖注入的所有经验教训。除其他事项外，这意味着：不使用全局变量，用“请求”对象替换超全局变量，不在“工厂”类之外使用`new`关键字，以及（当然）根据需要通过构造函数注入对象。

在使用“网关”找到一些候选代码之后，我们需要检查围绕“网关”使用的代码，以进行这些和其他操作：

+   数据的规范化、过滤、清理和验证

+   数据的计算、修改、创建和操作

+   使用数据进行顺序或并发操作和动作

+   保留来自这些操作和动作的成功/失败/警告/通知消息

+   保留值和变量以供以后的输入和输出

这些和其他逻辑片段很可能与领域相关。

要成功地将领域逻辑提取到一个或多个“交易”类和方法中，我们将不得不执行这些和其他活动：

+   分解或重新组织提取的领域逻辑以支持方法

+   分解或重新组织原始代码以包装新的“交易”调用

+   保留、返回或报告原始代码所需的数据

+   添加、更改或删除与提取的领域逻辑相关的原始代码中的变量

+   为“交易”类和方法创建和注入依赖项

### 注意

发现和提取最好被视为学习的过程。像这样拆解遗留应用程序是一种了解应用程序构造的方式。因此，我们不应害怕多次尝试提取。如果我们的第一次尝试失败，变得丑陋，或者结果不佳，我们应该毫不内疚地放弃工作，重新开始，学到更多关于什么有效和什么无效的知识。就我个人而言，我经常在完成对领域逻辑的提取之前进行两到三次尝试。这就是修订控制系统让我们的生活变得更加轻松的地方；我们可以分阶段工作，只有在满意结果时才提交，如果需要从干净的状态重新开始，可以回滚到较早的阶段。

### 提取示例

举例来说，回想一下我们在附录 B 中开始的代码，*网关之前的代码*。在本章的前面，我们提到我们已经将嵌入的 SQL 语句提取到*ArticlesGateway*类中，最终得到了附录 C 中的代码，*网关之后的代码*。现在我们从那里转到附录 D，*事务脚本之后的代码*，在那里我们已经将领域逻辑提取到一个`ArticleTransactions`类中。

提取的领域逻辑在其完成形式中似乎并不特别复杂，但实际工作起来却非常详细。请查看附录 C 和附录 D 进行比较。我们应该找到以下内容：

+   我们发现页面脚本中执行了两个单独的事务：一个用于提交新文章，一个用于更新现有文章。依次，这些都需要在数据库中操作用户的信用计数，以及各种数据规范化和支持操作。

+   我们将相关的领域逻辑提取到了一个`ArticleTransactions`类和两个单独的方法中，一个用于创建，一个用于更新。我们为`ArticleTransactions`方法命名，以执行领域逻辑，而不是为底层技术操作的实现命名。

+   输入过滤已封装为`ArticleTransactions`类中的支持方法，以便在两个事务方法中重复使用。

+   新的`ArticleTransactions`类接收`ArticlesGateway`和`UsersGateway`依赖项来管理数据库交互，而不是直接进行 SQL 调用。

+   一些仅与领域逻辑相关的变量已从页面脚本中删除，并作为属性放入`Transactions`类中。

+   原始页面脚本中的代码已大大减少。现在它基本上是一个对象创建和注入机制，将用户输入传递到领域层，并在稍后获取数据进行输出。

+   由于领域逻辑现在被封装起来，原始代码现在无法看到`$failure`变量，因为它在整个事务过程中被修改。该代码现在必须从`ArticleTransactions`类中获取失败信息，以供稍后呈现。

提取后，我们有一个`classes/`目录结构，看起来类似以下内容。这是在我们将 SQL 提取到`Gateway`类时使用领域导向的类结构的结果：

```php
**/path/to/app/classes/**
1 Domain/
2 Articles/
3 ArticlesGateway.php
4 ArticleTransactions.php
5 Users/
6 UsersGateway.php
```

### 注意

这不一定是我们最终的重构。`ArticleTransactions`的进一步修改仍然是可能的。例如，与其注入`UsersGateway`，也许将与用户相关的各种领域逻辑提取到`UserTransactions`类中并注入可能更有意义。`Transactions`方法之间仍然存在很多重复。我们还需要更好的错误检查和条件报告在`Transactions`方法中。这些和其他重构是次要的，只有在主要提取领域逻辑之后才会更加明显和更容易处理。

### 抽查剩余的原始代码

一旦我们从原始代码中提取了一个或多个*Transactions*，我们需要确保在使用*Transactions*而不是嵌入式领域逻辑时，原始代码能够正常工作。与以前一样，我们通过运行我们预先存在的特性测试来做到这一点。如果我们没有特性测试，我们必须浏览或以其他方式调用已更改的代码。如果这些测试失败，我们会感到高兴！我们发现了提取的错误，并有机会在部署到生产之前修复它。如果“测试”通过，我们同样会感到高兴，并继续前进。

### 为提取的事务编写测试

我们现在知道原始代码可以使用新提取的*Transactions*逻辑。然而，新的类和方法需要它们自己的一套测试。与提取领域逻辑相关的一切都一样，编写这些测试可能会很详细和苛刻。逻辑可能很复杂，有很多分支和循环。我们不应该因此而放弃测试。至少，我们需要编写覆盖领域逻辑的主要情况的测试。

如果必要，我们可以重构提取的逻辑，将它们分开成更容易测试的方法。分解提取的逻辑将使我们更容易看到流程并找到重复的逻辑元素。但是，我们必须记住，我们的目标是维护现有的行为，而不是改变遗留应用程序呈现的行为。

### 提示

有关如何使提取的逻辑更具可测试性的见解和技术，请参阅 Martin Fowler 等人的*重构*（[`refactoring.com/`](http://refactoring.com/)）以及 Michael Feathers 的*与遗留代码有效地工作*（[`www.amazon.com/Working-Effectively-Legacy-Michael-Feathers/dp/01311`](https://www.amazon.com/Working-Effectively-Legacy-Michael-Feathers/dp/01311)）。

### 再次抽查，提交，推送，通知 QA

最后，由于我们对提取的*Transactions*逻辑的测试和相关重构可能引入了一些意外的变化，我们再次使用我们的特性测试或以其他方式调用相关代码来抽查原始代码。如果这些失败，我们会感到高兴！我们发现了我们的更改并不像我们想象的那么好，我们有机会在代码和测试离我们太远之前纠正它们。

当原始代码测试和提取的*Transactions*测试都通过时，我们再次感到高兴！现在我们可以提交我们所有的新工作，将其推送到中央仓库，并通知 QA 我们的现代化代码已经准备好供他们审查。

### Do ... While

我们通过寻找在*Transactions*类之外使用的另一个*Gateway*来重新开始提取过程。我们继续提取和测试，直到所有*Gateway*调用发生在*Transactions*类内部。

## 常见问题

### 我们是在谈论 SQL 事务吗？

事务脚本一词指的是一种架构模式，并不意味着领域逻辑必须包装在 SQL 事务中。很容易混淆这两个概念。

话虽如此，牢记 SQL 事务可能有助于我们提取领域逻辑。一个有用的经验法则是，领域逻辑的各个部分应该根据它们在单个 SQL 事务中的适应程度进行拆分。假设的事务将作为一个整体提交或回滚。

这种目的的独特性将帮助我们确定领域逻辑的边界在哪里。我们实际上并没有添加 SQL 事务，只是以这种方式思考可以让我们对领域逻辑的边界有一些洞察。

### 重复的领域逻辑怎么办？

当我们将 SQL 语句提取到`Gateway`类时，有时会发现查询是相似但并非完全相同的。我们必须确定是否有办法将它们合并成一个方法。

同样，我们可能会发现我们的传统领域逻辑的某些部分已经被复制并粘贴到两个或更多的位置。当我们发现这些情况时，我们与`Gateway`类有相同的问题。这些逻辑片段是否足够相似，可以合并成一个方法，还是必须是不同的方法（甚至完全不同的`Transactions`）？

答案取决于具体情况。在某些情况下，重复的代码将是明显的逻辑复制，这意味着我们可以重用现有的`Transactions`方法。如果不是，我们需要提取到一个新的`Transactions`类或方法中。

还有一种中间路径，领域逻辑作为一个整体是不同的，但是在不同的“交易”中有相同的逻辑支持元素。在这些情况下，我们可以将支持逻辑重构为抽象基类`Transactions`类的方法，然后从中扩展新的`Transactions`。或者，我们可以将逻辑提取到一个支持类中，并将其注入到我们的`Transactions`中。

### 打印和回显是否属于领域逻辑的一部分？

我们的`Transactions`类不应该使用`print`或`echo`。领域逻辑应该只返回或保留数据。

当我们发现领域逻辑中间存在输出生成时，我们应该提取该部分，使其位于领域逻辑之外。一般来说，这意味着在`Transactions`类中收集输出，然后通过一个单独的方法返回它或使其可用。将输出生成留给表示层。

### 交易可以是一个类而不是一个方法吗？

在示例中，我们展示了*Transactions*作为与特定领域实体相关的一组方法，例如*ArticleTransactions*。与该实体相关的领域逻辑的每个部分都包装在一个类方法中。

然而，将领域逻辑分解为每个交易一个类的结构也是合理的。事实上，一些交易可能足够复杂，以至于它们确实需要它们自己的单独类。使用单个类来表示单个领域逻辑交易没有任何问题。

例如，之前的*ArticleTransactions*类可能被拆分为一个带有支持方法的抽象基类，以及为每个提取出的领域逻辑部分创建的两个具体类。每个具体类都扩展了*AbstractArticleTransaction*，如下所示：

```php
**classes/**
1 Domain/
2 Articles/
3 ArticlesGateway.php
4 Transaction/
5 AbstractArticleTransaction.php
6 SubmitNewArticleTransaction.php
7 UpdateExistingArticleTransaction.php
8 Users/
9 UsersGateway.php
```

如果我们采用每个交易一个类的方法，我们应该如何命名单个交易类上的主要方法，实际执行交易的方法？如果我们的传统代码库中已经存在主要方法的常见约定，我们应该遵守该约定。否则，我们需要选择一个一致的方法名称。个人而言，我喜欢利用`__invoke()`魔术方法来实现这个目的，但您可能希望使用`exec()`或其他适当的术语来指示我们正在执行或以其他方式执行交易。

### “Gateway”类中的领域逻辑怎么办？

当我们将 SQL 语句提取到`Gateway`类时，有可能将一些领域逻辑移入其中，而不是保留在原始位置。在我们重构工作的早期阶段，很容易混淆领域级输入过滤（确保数据符合特定领域状态）与数据库级过滤（确保数据可以安全地与数据库一起使用）。

现在我们可以更容易地区分这两者。如果我们发现我们的“网关”类中存在领域级别的逻辑，我们可能应该将其提取到我们的“交易”类中。我们需要确保相应的测试也要更新。

### 非领域类中嵌入的领域逻辑怎么办？

本章的示例显示了嵌入在页面脚本中的领域逻辑。同样可能的是，我们的类中也嵌入了领域逻辑。如果该类可以合理地被视为领域的一部分，并且仅包含与领域相关的逻辑，但未命名为领域，将该类移动到领域命名空间可能是明智的。

否则，如果该类除了领域逻辑之外还有其他责任，我们可以继续以与从页面脚本中提取逻辑相同的方式从中提取领域逻辑。提取后，原始类将需要将相关的“交易”类注入为依赖项。然后原始类应适当地调用“交易”。

# 回顾和下一步

在这一点上，我们已经将我们遗留代码库的核心，即位于我们应用程序中心的领域逻辑，提取到了自己独立且可测试的层中。这是我们现代化过程中最具挑战性的步骤，但这绝对是值得我们花费时间的。我们并没有对领域逻辑本身进行太多修改或改进。我们所做的任何更改都只是足够将数据输入到我们的新“交易”类中，然后再次用于后续使用。

在很多方面，我们所做的只是重新安排逻辑，使其能够独立地被访问。虽然领域逻辑本身可能仍然存在许多问题，但这些问题现在是*可测试*的问题。我们可以根据需要继续添加测试，以探索领域逻辑中的边缘情况。如果我们需要添加新的领域逻辑，我们可以创建或修改我们的“交易”类和方法来封装和测试该逻辑。

将领域逻辑提取到自己的层中的过程为我们进一步迭代地重构领域模型奠定了良好的基础。如果我们选择追求这一点，这种重构将引导我们走向更适合应用领域逻辑的架构。然而，该架构将取决于应用程序。有关为我们的应用程序开发良好领域模型的更多信息，请阅读 Eric Evans 的《领域驱动设计》（[`www.amazon.com/Domain-Driven-Design-Tackling-Complexity-Software/dp/0321125215`](https://www.amazon.com/Domain-Driven-Design-Tackling-Complexity-Software/dp/0321125215)）。

通过将领域逻辑提取到自己的层中，我们可以继续进行现代化过程的下一阶段。在这一点上，我们原始代码中只剩下了一些关注点。在这些关注点中，我们将下一个关注点放在呈现层上。


# 第十章：将演示逻辑提取到视图文件中

在传统应用程序中的页面脚本方面，很常见看到业务逻辑与演示逻辑交织在一起。例如，页面脚本做一些设置工作，然后包含一个头部模板，调用数据库，输出结果，计算一些值，打印计算出的值，将值写回数据库，并包含一个页脚模板。

我们已经采取了一些步骤，通过提取传统应用程序的域层，来解耦这些关注点。然而，在页面脚本中对域层的调用和其他业务逻辑仍然与演示逻辑混合在一起。除其他外，这种关注点的交织使得难以测试我们传统应用程序的不同方面。

在这一章中，我们将把所有的演示逻辑分离到自己的层中，这样我们就可以单独测试它，而不受业务逻辑的影响。

# 嵌入式演示逻辑

作为嵌入式演示逻辑的示例，我们可以看一下附录 E*收集演示逻辑之前的代码*。

演示逻辑。该代码显示了一个已经重构为使用域*Transactions*的页面脚本，但仍然在其余代码中存在一些演示逻辑。

### 注意

**演示逻辑和业务逻辑之间有什么区别？**

对于我们的目的，演示逻辑包括生成发送给用户（如浏览器或移动客户端）的任何和所有代码。这不仅包括`echo`和`print`，还包括`header()`和`setcookie()`。每个都会生成某种形式的输出。另一方面，“业务逻辑”是其他所有内容。

将演示逻辑与业务逻辑解耦的关键是将它们的代码放入单独的范围中。脚本应首先执行所有业务逻辑，然后将结果传递给演示逻辑。完成后，我们将能够单独测试我们的演示逻辑，而不受业务逻辑的影响。

为了实现这种范围的分离，我们将朝着在我们的页面脚本中使用`Response`对象的方向发展。我们所有的演示逻辑将在`Response`实例内执行，而不是直接在页面脚本中执行。这样做将为我们提供我们需要的范围分离，包括 HTTP 头和 cookie 在内的所有输出生成，与页面脚本的其余部分分离开来。

### 注意

**为什么使用 Response 对象？**

通常，当我们想到演示时，我们会想到一个视图或模板系统，为我们呈现内容。然而，这些类型的系统通常不会封装将发送给用户的完整输出集。我们不仅需要输出 HTTP 主体，还需要输出 HTTP 头。此外，我们需要能够测试是否设置了正确的头部，并且内容已经生成正确。因此，在这一点上，`Response`对象比单独的视图或模板系统更合适。对于我们的`Response`对象，我们将使用[`mlaphp.com/code`](http://mlaphp.com/code)提供的类。请注意，我们将在*Response*上下文中包含文件，这意味着该对象上的方法将对在该对象“内部”运行的`include`文件可用。

## 提取过程

提取演示逻辑并不像提取域逻辑那么困难。然而，它需要仔细的注意和大量的测试。

一般来说，流程如下：

1.  找到一个包含演示逻辑混合在其余代码中的页面脚本。

1.  在那个脚本中，重新排列代码，将所有演示逻辑收集到文件中所有其他逻辑之后的一个单独的块中，然后对重新排列的代码进行抽查。

1.  将演示逻辑块提取到视图文件中，通过`Response`进行交付，并再次对脚本进行抽查，以确保脚本能够正确地与新的`Response`一起工作。

1.  对演示逻辑进行适当的转义并再次进行抽查。

1.  提交新代码，推送到公共存储库，并通知 QA。

1.  重新开始包含演示逻辑混合在其他非演示代码中的下一个页面脚本。

### 搜索嵌入式演示逻辑

一般来说，我们应该很容易找到我们遗留应用程序中的演示逻辑。在这一点上，我们应该对代码库足够熟悉，以便大致知道页面脚本生成的输出在哪里。

如果我们需要一个快速启动，我们可以使用项目范围的搜索功能来查找所有`echo`、`print`、`printf`、`header`、`setcookie`和`setrawcookie`的出现。其中一些可能出现在类方法中；我们将在以后解决这个问题。现在，我们将集中精力在页面脚本上，这些调用发生在这些调用发生的地方。

### 重新排列页面脚本并进行抽查

现在我们有了一个候选的页面脚本，我们需要重新排列代码，以便演示逻辑和其他所有内容之间有一个清晰的分界线。在这个例子中，我们将使用附录 E 中的代码，*收集之前的代码*。

首先，我们转到文件底部，并在最后一行添加一个`/* PRESENTATION */`注释。然后我们回到文件顶部。逐行和逐块地工作，将所有演示逻辑移动到文件末尾，在我们的`/* PRESENTATION */`注释之后。完成后，`/* PRESENTATION */`注释之前的部分应该只包含业务逻辑，之后的部分应该只包含演示逻辑。

鉴于我们在附录 E 中的起始代码，*收集之前的代码*，我们应该最终得到类似附录 F 中的代码，*收集之后的代码*。特别要注意的是，我们有以下内容：

+   将业务逻辑未使用的变量，如`$current_page`，移到演示块下

+   将`header.php`包含移到演示块下

+   将仅对演示变量起作用的逻辑和条件，如设置`$page_title`的`if`，移到演示块中

+   用一个`$action`变量替换`$_SERVER['PHP_SELF']`

+   用一个`$id`变量替换`$_GET['id']`

### 注意

在创建演示块时，我们应该小心遵循我们从早期章节中学到的所有课程。即使演示代码是文件中的一个块（而不是一个类），我们也应该将该块视为类方法。除其他事项外，这意味着不使用全局变量、超全局变量或`new`关键字。这将使我们在以后将演示块提取到视图文件时更容易。

现在我们已经重新排列了页面脚本，使得所有演示逻辑都集中在最后，我们需要进行抽查，以确保页面脚本仍然正常工作。通常情况下，我们通过运行我们预先存在的特性测试来做到这一点。如果没有，我们必须浏览或以其他方式调用已更改的代码。

如果页面生成的输出与以前不同，我们的重新排列在某种程度上改变了逻辑。我们需要撤消并重新进行重新排列，直到页面按照应该的方式工作。

一旦我们的抽查成功，我们可能希望提交到目前为止的更改。如果我们接下来的一系列更改出现问题，我们可以将代码恢复到这一点作为已知的工作状态。

## 提取演示到视图文件并进行抽查

现在我们有了一个带有所有演示逻辑的工作页面脚本，我们将把整个块提取到自己的文件中，然后使用`Response`来执行提取的逻辑。

### 创建一个 views/目录

首先，我们需要一个地方来放置我们传统应用程序中的视图文件。虽然我更喜欢将呈现逻辑保持在业务逻辑附近，但这种安排将给我们在以后的现代化步骤中带来麻烦。因此，我们将在我们的传统应用程序中创建一个名为`views/`的新目录，并将我们的视图文件放在那里。该目录应该与我们的`classes/`和`tests/`目录处于同一级别。例如：

```php
**/path/to/app/**
1 classes/
2 tests/
3 views/
```

#### 选择一个视图文件名称

现在我们有一个保存视图文件的地方，我们需要为即将提取的呈现逻辑选择一个文件名。视图文件应该以页面脚本命名，在`views/`下的路径应与页面脚本路径匹配。例如，如果我们从`/foo/bar/baz.php`页面脚本中提取呈现，目标视图文件应保存在`/views/foo/bar/baz.php`。

有时，除了`.php`之外，使用其他扩展名对于我们的视图文件也是有用的。我发现使用一个指示视图格式的扩展名可能会有所帮助。例如，生成 HTML 的视图可能以`.html.php`结尾，而生成 JSON 的视图可能以`.json.php`结尾。

#### 将呈现块移动到视图文件中

接下来，我们从页面脚本中剪切呈现块，并将其原样粘贴到我们的新视图文件中。

然后，在页面脚本中原始的呈现块的位置，我们在新的视图文件中创建一个`Response`对象，并用`setView()`指向我们的视图文件。我们还为以后设置了一个空的`setVars()`调用，最后调用了`send()`方法。

### 注意

我们应该*始终*在所有页面脚本中使用相同的变量名来表示*Response*对象。这里的所有示例都将使用名称`$response`。这不是因为名称`$response`很特别，而是因为这种一致性在以后的章节中将非常重要。

例如：

```php
foo/bar/baz.php
1 <?php
2 // ... business logic ...
3
4 /* PRESENTATION */
5 $response = new \Mlaphp\Response('/path/to/app/views');
6 $response->setView('foo/bar/baz.html.php');
7 $response->setVars(array());
8 $response->send();
9 ?>
```

此时，我们已成功将呈现逻辑与页面脚本解耦。我们可以删除`/* PRESENTATION */`注释。它已经达到了它的目的，不再需要。

然而，这种解耦基本上破坏了呈现逻辑，因为视图文件依赖于页面脚本中的变量。考虑到这一点，我们开始进行抽查和修改周期。我们浏览或以其他方式调用页面脚本，并发现特定变量对于呈现不可用。我们将其添加到`setVars()`数组中，并再次进行抽查。我们继续向`setVars()`数组添加变量，直到视图文件拥有所需的一切，我们的抽查运行变得完全成功。

### 注意

在这个过程的这一部分，最好设置`error_reporting(E_ALL)`。这样我们将得到每个未初始化变量在呈现逻辑中的 PHP 通知。

鉴于我们之前在附录 E 中的示例，*收集之前的代码*和附录 F 中的示例，*收集之后的代码*，我们最终到达附录 G，*响应视图文件之后的代码*。我们可以看到`articles.html.php`视图文件需要四个变量：`$id, $failure`, `$input`, 和 `$action`：

```php
1 <?php
2 // ...
3 $response->setVars(array(
4 'id' => $id,
5 'failure' => $article_transactions->getFailure(),
6 'input' => $article_transactions->getInput(),
7 'action' => $_SERVER['PHP_SELF'],
8 ));
9 // ...
10 ?>
```

一旦我们有一个工作的页面脚本，我们可能希望再次提交我们的工作，以便以后如果需要，我们有一个已知正确的状态可以回滚。

### 添加适当的转义

不幸的是，大多数传统应用程序很少或根本不关注输出安全性。最常见的漏洞之一是**跨站脚本**（**XSS**）。

### 注意

什么是 XSS？

跨站脚本攻击是一种可能是由用户输入导致的攻击。例如，攻击者可以在表单输入或 HTTP 标头中输入恶意构造的 JavaScript 代码。如果该值然后在未经逃逸的情况下传递回浏览器，浏览器将执行该 JavaScript 代码。这有可能使客户端浏览器暴露于进一步的攻击。有关更多信息，请参阅*OWASP 关于 XSS 的条目* ([`www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29`](https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29))。

防御 XSS 的方法是始终为使用的上下文逃逸所有变量。如果一个变量用作 HTML 内容，它需要作为 HTML 内容进行逃逸；如果一个变量用作 HTML 属性，它需要逃逸为 HTML 属性，依此类推。

防御 XSS 需要开发人员的勤奋。如果我们记住逃逸输出的一件事，那就应该是`htmlspecialchars()`函数。适当使用此函数将使我们免受大多数 XSS 攻击的侵害。

使用`htmlspecialchars()`时，我们必须确保每次传递引号常量和字符集。因此，仅调用`htmlspecialchars($unescaped_text)`是不够的。我们必须调用`htmlspecialchars($unescaped_text, ENT_QUOTES, 'UTF-8')`。因此，输出看起来像这样：

```php
**unescaped.html.php**
1 <form action="<?php
2 echo $request->server['PHP_SELF'];
3 ?>" method="POST">
```

这需要像这样进行逃逸：

```php
**escaped.html.php**
1 <form action="<?php
2 echo htmlspecialchars(
3 $request->server['PHP_SELF'],
4 ENT_QUOTES,
5 'UTF-8'
6 );
7 ?>" method="POST">
```

每当我们发送未经逃逸的输出时，我们需要意识到我们很可能会打开一个安全漏洞。因此，我们必须对我们用于输出的每个变量应用逃逸。

以这种方式重复调用`htmlspecialchars()`可能很麻烦，因此`Response`类提供了一个`esc()`方法，作为`htmlspecialchars()`的别名，并带有合理的设置：

```php
**escaped.php**
1 <form action="<?php
2 echo $this->esc($request->server['PHP_SELF']);
3 ?>" method="POST">
```

请注意，通过`htmlspecialchars()`进行逃逸只是一个起点。虽然逃逸本身很简单，但很难知道特定上下文的适当逃逸技术。

很遗憾，本书的范围不包括提供逃逸和其他安全技术的全面概述。有关更多信息以及一个很好的独立逃逸工具，请参阅*Zend\Escaper* ([`framework.zend.com/manual/2.2/en/modules/zend.escaper`](https://framework.zend.com/manual/2.2/en/modules/zend.escaper)) 库。

在我们逃逸`Response`视图文件中的所有输出之后，我们可以继续进行测试。

## 编写视图文件测试

为视图文件编写测试提出了一些独特的挑战。在本章之前，我们所有的测试都是针对类和类方法的。因为我们的视图文件是*文件*，所以我们需要将它们放入稍微不同的测试结构中。

### tests/views/目录

首先，我们需要在我们的`tests/`目录中创建一个`views/`子目录。之后，我们的`tests/`目录应该看起来像这样：

```php
**/path/to/app/tests/**
1 bootstrap.php
2 classes/
3 phpunit.xml
4 views/
```

接下来，我们需要修改`phpunit.xml`文件，以便它知道要扫描新的`views/`子目录进行测试：

```php
**tests/phpunit.xml**
1 <phpunit bootstrap="./bootstrap.php">
2 <testsuites>
3 <testsuite>
4 <directory>./classes</directory>
5 <directory>./views</directory>
6 </testsuite>
7 </testsuites>
8 </phpunit>
```

#### 编写视图文件测试

现在我们有了视图文件测试的位置，我们需要编写一个。

尽管我们正在测试一个文件，但是 PHPUnit 要求每个测试都是一个类。因此，我们将为正在测试的视图文件命名我们的测试，并将其放在`tests/views/`目录下，该目录模仿原始视图文件的位置。例如，如果我们有一个视图文件位于`views/foo/bar/baz.html.php`，我们将在`tests/views/foo/bar/`创建一个测试文件`BazHtmlTest.php`。是的，这有点丑陋，但这将帮助我们跟踪哪些测试与哪些视图相对应。

在我们的测试类中，我们将创建一个`Response`实例，就像我们页面脚本末尾的那个一样。我们将传递视图文件路径和所需的变量。最后，我们将要求视图，然后检查输出和标头，以查看视图是否正常工作。

考虑到我们的`articles.html.php`文件，我们的初始测试可能如下所示：

```php
**tests/views/ArticlesHtmlTest.php**
1 <?php
2 class ArticlesHtmlTest extends \PHPUnit_Framework_TestCase
3 {
4 protected $response;
5 protected $output;
6
7 public function setUp()
8 {
9 $this->response = new \Mlaphp\Response('/path/to/app/views');
10 $this->response->setView('articles.html.php');
11 $this->response->setVars(
12 'id' => '123',
13 'failure' => array(),
14 'action' => '/articles.php',
15 'input' => array(
16 'title' => 'Article Title',
17 'body' => 'The body text of the article.',
18 'max_ratings' => 5,
19 'credits_per_rating' => 1,
20 'notes' => '...',
21 'ready' => 0,
22 ),
23 );
24 $this->output = $this->response->requireView();
25 }
26
27 public function testBasicView()
28 {
29 $expect = '';
30 $this->assertSame($expect, $this->output);
31 }
32 }
33 ?>
```

### 注意

**为什么使用 requireView()而不是 send()?**

如果我们使用`send()`，`Response`将输出视图文件的结果，而不是将它们留在缓冲区供我们检查。调用`requireView()`会调用视图文件，但返回结果而不是生成输出。

当我们运行这个测试时，它会失败。我们会感到高兴，因为`$expect`的值为空，但输出应该有很多内容。这是正确的行为。（如果测试通过，可能有什么地方出错了。）

#### 断言内容的正确性

现在我们需要我们的测试来查看输出是否正确。

最简单的方法是转储实际的`$this->output`字符串，并将其值复制到`$expect`变量中。如果输出字符串相对较短，使用`assertSame($expect, $this->output)`来确保它们是相同的应该完全足够。

然而，如果我们主视图文件包含的任何其他文件发生了变化，那么测试将失败。失败不是因为主视图已经改变，而是因为相关视图已经改变。这不是对我们有帮助的失败。

对于大型输出字符串，我们可以查找预期的子字符串，并确保它在实际输出中存在。然后，当测试失败时，它将与我们正在测试的特定子字符串相关，而不是整个输出字符串。

例如，我们可以使用`strpos()`来查看特定字符串是否在输出中。如果`$this->output`的大堆中不包含`$expect`针，`strpos()`将返回布尔值`false`。任何其他值都表示`$needle`存在。（如果我们编写自己的自定义断言方法，这种逻辑更容易阅读。）

```php
1 <?php
2 public function assertOutputHas($expect)
3 {
4 if (strpos($this->output, $expect) === false) {
5 $this->fail("Did not find expected output: $expect");
6 }
7 }
8
9 public function testFormTag()
10 {
11 $expect = '<form method="POST" action="/articles.php">';
12 $this->assertOutputHas($expect);
13 }
14 ?>
```

这种方法的好处是非常直接，但可能不适用于复杂的断言。我们可能希望计算元素出现的次数，或者断言 HTML 具有特定的结构而不引用该结构的内容，或者检查元素是否出现在输出的正确位置。

对于这些更复杂的内容断言，PHPUnit 有一个`assertSelectEquals()`断言，以及其他相关的`assertSelect*()`方法。这些方法通过使用 CSS 选择器来检查输出的不同部分，但可能难以阅读和理解。

或者，我们可能更喜欢安装`Zend\Dom\Query`来更精细地操作 DOM 树。这个库也通过使用 CSS 选择器来拆分内容。它返回`DOM`节点和节点列表，这使得它非常适用于以细粒度的方式测试内容。

不幸的是，我无法就哪种方法对您最好给出具体建议。我建议从上面的`assertOutputHas()`方法类似的方法开始，当明显需要更强大的系统时，再转向`Zend\Dom\Query`方法。

在我们编写了确认演示工作正常的测试之后，我们继续进行流程的最后一部分。

### 提交，推送，通知 QA

在这一点上，我们应该对页面脚本和提取的演示逻辑进行了测试。现在我们提交所有的代码和测试，将它们推送到公共存储库，并通知 QA 我们已经准备好让他们审查新的工作。

### Do ... While

我们继续在页面脚本中寻找混合业务逻辑和演示逻辑。当我们通过`Response`对象将所有演示逻辑提取到视图文件中时，我们就完成了。

## 常见问题

### 关于头部和 Cookies 呢？

在上面的例子中，我们只关注了`echo`和`print`的输出。然而，通常情况下，页面脚本还会通过`header()`、`setcookie()`和`setrawcookie()`设置 HTTP 头部。这些也会生成输出。

处理这些输出方法可能会有问题。`Response`类使用`输出缓冲`将`echo`和`print`捕获到返回值中，但对于`header()`和相关函数的调用，没有类似的选项。因为这些函数的输出没有被缓冲，我们无法轻松地测试看到发生了什么。

这是一个`Response`对象真正帮助我们的地方。该类带有缓冲`header()`和相关本机 PHP 函数的方法，但直到`send()`时才调用这些函数。这使我们能够捕获这些调用的输入并在它们实际激活之前进行测试。

例如，假设我们在一个虚构的视图文件中有这样的代码：

```php
**foo.json.php**
1 <?php
2 header('Content-Type: application/json');
3 setcookie('baz', 'dib');
4 setrawcookie('zim', 'gir');
5 echo json_encode($data);
6 ?>
```

除其他事项外，我们无法测试头部是否符合预期。PHP 已经将它们发送给客户端。

在使用*Response*对象的视图文件时，我们可以使用`$this->`前缀来调用*Response*方法，而不是本机 PHP 函数。*Response*方法缓冲本机调用的参数，而不是直接进行调用。这使我们能够在它们作为输出之前检查参数。

```php
**foo.json.php**
1 <?php
2 $this->header('Content-Type: application/json');
3 $this->setcookie('baz', 'dib');
4 $this->setrawcookie('zim', 'gir');
5 echo json_encode($data);
6 ?>
```

### 注意

因为视图文件是在*Response*实例内执行的，所以它可以访问`$this`来获取`Response`属性和方法。`Response`对象上的`header()`、`setcookie()`和`setrawcookie()`方法具有与本机 PHP 方法完全相同的签名，但是它们将输入捕获到属性中以便稍后输出，而不是立即生成输出。

现在我们可以测试`Response`对象来检查 HTTP 正文以及 HTTP 头部。

```php
**tests/views/FooJsonTest.php**
1 <?php
2 public function test()
3 {
4 // set up the response object
5 $response = new \Mlaphp\Response('/path/to/app/views');
6 $response->setView('foo.json.php');
7 $response->setVars('data', array('foo' => 'bar'));
8
9 // invoke the view file and test its output
10 $expect_body = '{"foo":"bar"}';
11 $actual_body = $response->requireView();
12 $this->assertSame($expect_output, $actual_output);
13
14 // test the buffered HTTP header calls
15 $expect_headers = array(
16 array('header', 'Content-Type: application/json'),
17 array('setcookie', 'baz', 'dib'),
18 array('setrawcookie', 'zim', 'gir'),
19 );
20 $actual_headers = $response->getHeaders();
21 $this->assertSame($expect_output, $actual_output);
22 }
23 ?>
```

### 注意

*Response*的`getHeaders()`方法返回一个子数组的数组。每个子数组都有一个元素 0，表示要调用的本机 PHP 函数名称，其余元素是函数的参数。这些是将在`send()`时调用的函数调用。

## 如果我们已经有一个模板系统呢？

许多时候，遗留应用程序已经有一个视图或模板系统。如果是这样，保持使用现有的模板系统可能就足够了，而不是引入新的`Response`类。

如果我们决定保留现有的模板系统，则本章的其他步骤仍然适用。我们需要将所有模板调用移动到页面脚本末尾的一个位置，将所有模板交互与其他业务逻辑分离。然后我们可以在页面脚本末尾显示模板。例如：

```php
**foo.php**
1 <?php
2 // ... business logic ...
3
4 /* PRESENTATION */
5 $template = new Template;
6 $template->assign($this->getVars());
7 $template->display('foo.tpl.php');
8 ?>
```

如果我们不发送 HTTP 头部，这种方法与使用`Response`对象一样具有可测试性。然而，如果我们混合调用`header()`和相关函数，我们的可测试性将更受限制。

为了未来保护我们的遗留代码，我们可以将模板逻辑移到视图文件中，并在页面脚本中与`Response`对象交互。例如：

```php
**foo.php**
1 <?php
2 // ... business logic ...
3
4 /* PRESENTATION */
5 $response = new Response('/path/to/app/views');
6 $response->setView('foo.html.php');
7 $response->setVars(array('foo' => $foo));
8 $response->send();
9 ?>
```

```php
**foo.html.php**
1 <?php
2 // buffer calls to HTTP headers
3 $this->setcookie('foo', 'bar');
4 $this->setrawcookie('baz', 'dib');
5
6 // set up the template object with Response vars
7 $template = new Template;
8 $template->assign($this->getVars());
9
10 // display the template
11 $template->display('foo.tpl.php');
12 ?>
```

这使我们能够继续使用现有的模板逻辑和文件，同时通过`Response`对象为 HTTP 头部添加可测试性。

为了保持一致，我们应该使用现有的模板系统或者通过`Response`对象在视图文件中包装所有模板逻辑。我们不应该在一些页面脚本中使用模板系统，在其他页面脚本中使用`Response`对象。在后面的章节中，我们在页面脚本中与呈现层交互的方式将变得很重要。

### 流式内容怎么办？

大多数情况下，我们的呈现内容足够小，可以由 PHP 缓冲到内存中，直到准备发送。然而，有时我们的遗留应用程序可能需要发送大量数据，比如几十或几百兆字节的文件。

将大文件读入内存，以便我们可以将其输出给用户通常不是一个好的方法。相反，我们流式传输文件：我们读取文件的一小部分并将其发送给用户，然后读取下一小部分并将其发送给用户，依此类推，直到整个文件被传送。这样，我们就不必将整个文件保存在内存中。

到目前为止，示例只处理了将视图缓冲到内存中，然后一次性输出，而不是流式传输。对于视图文件来说，将整个资源读入内存然后输出是一个不好的方法。与此同时，我们需要确保在任何流式内容之前传送标头。

`Response`对象有一个处理这种情况的方法。`Response`方法`setLastCall()`允许我们设置一个用户定义的函数（可调用的），以在需要视图文件并发送标头后调用。有了这个，我们可以传递一个类方法来为我们流式传输资源。

例如，假设我们需要流式传输一个大图像文件。我们可以编写一个类来处理流逻辑，如下所示：

```php
**classes/FileStreamer.php**
1 <?php
2 class FileStreamer
3 {
4 public function send($file, $dest = STDOUT)
5 {
6 $fh = fopen($file, 'rb');
7 while (! feof($fh)) {
8 $data = fread($fh, 8192);
9 fwrite($dest, $data);
10 }
11 fclose($fh);
12 }
13 }
14 ?>
```

这里还有很多需要改进的地方，比如错误检查和更好的资源处理，但它完成了我们示例的目的。

我们可以在页面脚本中创建一个*FileStreamer*的实例，视图文件可以将其用作`setLastCall()`的可调用参数：

```php
**foo.php**
1 <?php
2 // ... business logic ...
3 $file_streamer = new FileStreamer;
4 $image_file = '/path/to/picture.tiff';
5 $content_type = 'image/tiff';
6
7 /* PRESENTATION */
8 $response = new Response('/path/to/app/views');
9 $response->setView('foo.stream.php');
10 $response->setVars(array(
11 'streamer' => $file_streamer,
12 'file' => $image_file,
13 'type' => $content_type,
14 ));
15 ?>
```

```php
**views/foo.stream.php**
1 <?php
2 $this->header("Content-Type: {$type}");
3 $this->setLastCall(array($streamer, 'send'), $file);
4 ?>
```

在`send()`时，`Response`将需要视图文件，设置一个标头和最后一个调用的参数。然后，`Response`发送标头和视图的捕获输出（在这种情况下是空的）。最后，它调用`setLastCall()`中的可调用和参数，流式传输文件。

## 如果我们有很多演示变量怎么办？

在本章的示例代码中，我们只有少数变量需要传递给演示逻辑。不幸的是，更有可能的情况是需要传递 10 个、20 个或更多的变量。这通常是因为演示由几个`include`文件组成，每个文件都需要自己的变量。

这些额外的变量通常用于诸如站点标题、导航和页脚部分之类的内容。因为我们已经将业务逻辑与演示逻辑解耦，并在一个单独的范围内执行演示逻辑，所以我们必须传递所有`include`文件所需的变量。

比如说我们有一个视图文件，其中包括一个`header.php`文件，就像这样：

```php
**header.php**
1 <html>
2 <head>
3 <title><?php
4 echo $this->esc($page_title);
5 ?></title>
6 <link rel="stylesheet" href="<?php
7 echo $this->esc($page_style);
8 ?>"></link>
9 </head>
10 <body>
11 <h1><?php echo $this->esc($page_title); ?></h1>
12 <div id="navigation">
13 <ul>
14 <?php foreach ($site_nav as $nav_item) {
Extract Presentation Logic To View Files 117
15 $href = $this->esc($nav_item['href']);
16 $name = $this->esc($nav_item['name']);
17 echo '<li><a href="' . $href
18 . '"/a>' . $name
19 . '</li>' . PHP_EOL;
20 }?>
21 </ul>
22 </div>
23 <!-- end of header.php -->
```

我们的页面脚本将不得不传递`$page_title`、`$page_style`和`$site_nav`变量，以便页眉正确显示。这是一个相对温和的情况；可能会有更多的变量。

一个解决方案是将常用变量收集到一个或多个自己的对象中。然后我们可以将这些常用对象传递给`Response`供视图文件使用。例如，特定于页眉的显示变量可以放在`HeaderDisplay`类中，然后传递给`Response`。

```php
classes/HeaderDisplay.php
1 <?php
2 class HeaderDisplay
3 {
4 public $page_title;
5 public $page_style;
6 public $site_nav;
7 }
8 ?>
```

然后我们可以修改`header.php`文件以使用*HeaderDisplay*对象，页面脚本可以传递*HeaderDisplay*的实例，而不是所有单独的与页眉相关的变量。

### 提示

一旦我们开始将相关变量收集到类中，我们将开始看到如何将演示逻辑收集到这些类的方法中，从而减少视图文件中的逻辑量。例如，我们应该很容易想象在*HeaderDisplay*类上有一个`getNav()`方法，它返回我们导航小部件的正确 HTML。

### 那么生成输出的类方法怎么办？

在本章的示例代码中，我们集中在页面脚本中的呈现逻辑。然而，可能情况是，领域类或其他支持类使用`echo`或`header()`来生成输出。因为输出生成必须限制在呈现层，我们需要找到一种方法来移除这些调用，而不破坏我们的遗留应用程序。即使是用于呈现目的的类也不应该自行生成输出。

这里的解决方案是将每个`echo`、`print`等的使用转换为`return`。然后我们可以立即输出结果，或者将结果捕获到一个变量中，稍后再输出。

例如，假设我们有一个类方法看起来像这样：

```php
1 <?php
2 public function namesAndRoles($list)
3 {
4 echo "<p>Names and roles:</p>";
5 foreach ($list as $item) {
6 echo "<dl>";
7 echo "<dt>Name</dt><dd>{$item['name']}</dd>";
8 echo "<dt>Role</dt><dd>{$item['role']}</dd>";
9 echo "</dl>";
10 }
11 }
12 ?>
```

我们可以将其转换为类似于这样的东西（并记得添加转义！）：

```php
1 <?php
2 public function namesAndRoles($list)
3 {
4 $html = "<p>Names and roles:</p>";
5 foreach ($list as $item) {
6 $name = htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8');
7 $role = htmlspecialchars($item['role'], ENT_QUOTES, 'UTF-8');
8 $html .= "<dl>";
9 $html .= "<dt>Name</dt><dd>{$name}</dd>";
10 $html .= "<dt>Role</dt><dd>{$role}</dd>";
11 $html .= "</dl>";
12 }
13 return $html;
14 }
15 ?>
```

## 业务逻辑混入呈现逻辑怎么办？

当重新排列页面脚本以将业务逻辑与呈现逻辑分开时，我们可能会发现呈现代码调用*Transactions*或其他类或资源。这是一种混合关注点的恶劣形式，因为呈现依赖于这些调用的结果。

如果被调用的代码专门用于输出，那么就没有问题；我们可以保留调用。但是，如果被调用的代码与数据库或网络连接等外部资源进行交互，那么我们就需要分离关注点。

解决方案是从呈现逻辑中提取出一组等效的业务逻辑调用，将结果捕获到一个变量中，然后将该变量传递给呈现。

举个假设的例子，以下混合代码进行数据库调用，然后在一个循环中呈现它们：

```php
1 <?php
2 /* PRESENTATION */
3 foreach ($post_transactions->fetchTopTenPosts() as $post) {
4 echo "{$post['title']} has "
5 . $comment_transactions->fetchCountForPost($post['id'])
6 . " comments.";
7 }
8 ?>
```

暂时忽略我们需要解决示例中提出的 N+1 查询问题，以及这可能更好地在*Transactions*级别解决。我们如何将呈现与数据检索分离？

在这种情况下，我们构建了一组等效的代码来捕获所需的数据，然后将该数据传递给呈现逻辑，并应用适当的转义。

```php
1 <?php
2 // ...
3 $posts = $post_transactions->fetchTopTenPosts();
4 foreach ($posts as &$post) {
5 $count = $comment_transactions->fetchCountForPost($post['id']);
6 $post['comment_count'] = $count;
7 }
8 // ...
9
10 /* PRESENTATION */
11 foreach ($posts as $post) {
12 $title = $this->esc($post['title']);
13 $comment_count = $this->esc($post['comment_count']);
14 echo "{$title} has {$comment_count} comments."
15 }
16 ?>
```

是的，我们最终会两次循环相同的数据——一次在业务逻辑中，一次在呈现逻辑中。虽然从某些方面来说，这可能被称为低效，但效率不是我们的主要目标。关注点的分离是我们的主要目标，这种方法很好地实现了这一点。

### 如果一个页面只包含呈现逻辑呢？

我们遗留应用程序中的一些页面可能主要或完全由呈现代码组成。在这些情况下，似乎我们不需要*Response*对象。

然而，即使这些页面脚本也应该转换为使用*Response*和视图文件。我们现代化过程中的后续步骤将需要一个一致的接口来处理我们的页面脚本的结果，我们的*Response*对象是确保这种一致性的方法。

# 审查和下一步

我们现在已经浏览了所有的页面脚本，并将呈现逻辑提取到一系列单独的文件中。呈现代码现在在一个完全独立于页面脚本的范围内执行。这使我们非常容易看到脚本的剩余逻辑，并独立测试呈现逻辑。

将呈现逻辑提取到自己的层中后，我们的页面脚本正在减小。它们中所剩的只是一些设置工作和准备响应所需的操作逻辑。

那么，我们的下一步是将页面脚本中剩余的操作逻辑提取到一系列控制器类中。
