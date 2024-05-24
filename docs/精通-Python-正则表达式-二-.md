# 精通 Python 正则表达式（二）

> 原文：[`zh.annas-archive.org/md5/3C085EA0447FEC36F167335BDBD4428E`](https://zh.annas-archive.org/md5/3C085EA0447FEC36F167335BDBD4428E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：分组

分组是一个强大的工具，允许您执行诸如以下操作：

+   创建子表达式以应用量词。例如，重复子表达式而不是单个字符。

+   限制交替的范围。我们可以定义确切需要交替的内容，而不是整个表达式交替。

+   从匹配的模式中提取信息。例如，从订单列表中提取日期。

+   再次在正则表达式中使用提取的信息，这可能是最有用的属性。一个例子是检测重复的单词。

在本章中，我们将探讨分组，从最简单的到最复杂的。我们将回顾一些先前的示例，以便清楚地了解这些操作的工作原理。

# 介绍

我们已经在第二章 *使用 Python 的正则表达式*中的几个示例中使用了分组。分组是通过两个元字符`()`来完成的。使用括号的最简单示例将构建子表达式。例如，假设您有一个产品列表，每个产品的 ID 由一个数字序列和一个字母数字字符组成，例如 1-a2-b：

```py
>>>re.match(r"(\d-\w){2,3}", ur"1-a2-b")
<_sre.SRE_Match at 0x10f690738>
```

如您在前面的示例中所见，括号指示正则表达式引擎，其中它们内部的模式必须被视为一个单元。

让我们看另一个例子；在这种情况下，我们需要匹配每当有一个或多个`ab`后跟`c`时：

```py
>>>re.search(r"(ab)+c", ur"ababc")
<_sre.SRE_Match at 0x10f690a08>
>>>re.search(r"(ab)+c", ur"abbc")
None
```

因此，您可以在主模式中使用括号来分组有意义的子模式。

它也可以用来限制交替的范围。例如，假设我们想要编写一个表达式来匹配是否有人来自西班牙。在西班牙语中，国家名称是 España，西班牙人是 Español。因此，我们想要匹配 España 和 Español。西班牙字母ñ对于非西班牙人来说可能会令人困惑，因此为了避免混淆，我们将使用 Espana 和 Espanol 代替 España 和 Español。

我们可以通过以下交替实现：

```py
>>>re.search("Espana|ol", "Espanol")
<_sre.SRE_Match at 0x1043cfe68>
>>>re.search("Espana|ol", "Espana")
<_sre.SRE_Match at 0x1043cfed0>
```

问题是这也匹配了`ol`：

```py
>>>re.search("Espana|ol", "ol")
<_sre.SRE_Match at 0x1043cfe00>
```

因此，让我们尝试字符类，如下面的代码所示：

```py
>>>re.search("Espan[aol]", "Espanol")
<_sre.SRE_Match at 0x1043cf1d0>

>>>re.search("Espan[aol]", "Espana")
<_sre.SRE_Match at 0x1043cf850>
```

它有效，但这里我们有另一个问题：它还匹配了`"Espano"`和`"Espanl"`，这在西班牙语中没有任何意义：

```py
>>>re.search("Espan[a|ol]", "Espano")
<_sre.SRE_Match at 0x1043cfb28>
```

解决方案是使用括号：

```py
>>>re.search("Espan(a|ol)", "Espana")
<_sre.SRE_Match at 0x10439b648>

>>>re.search("Espan(a|ol)", "Espanol")
<_sre.SRE_Match at 0x10439b918>

>>>re.search("Espan(a|ol)", "Espan")
   None

>>>re.search("Espan(a|ol)", "Espano")
   None

>>>re.search("Espan(a|ol)", "ol")
   None
```

让我们看看分组的另一个关键特性，**捕获**。组还捕获匹配的模式，因此您可以在以后的几个操作中使用它们，例如`sub`或正则表达式本身。

例如，假设您有一个产品列表，其 ID 由代表产品国家的数字、作为分隔符的破折号和一个或多个字母数字字符组成。您被要求提取国家代码：

```py
>>>pattern = re.compile(r"(\d+)-\w+")
>>>it = pattern.finditer(r"1-a\n20-baer\n34-afcr")
>>>match = it.next()
>>>match.group(1)
'1'
>>>match = it.next()
>>>match.group(1)
'20'
>>>match = it.next()
>>>match.group(1)
'34'
```

在前面的示例中，我们创建了一个模式来匹配 ID，但我们只捕获了由国家数字组成的一个组。请记住，在使用`group`方法时，索引 0 返回整个匹配，而组从索引 1 开始。

捕获组由于可以与几个操作一起使用而提供了广泛的可能性，我们将在接下来的部分中讨论它们的使用。

# 反向引用

正如我们之前提到的，分组给我们提供的最强大的功能之一是可以在正则表达式或其他操作中使用捕获的组。这正是反向引用提供的。为了带来一些清晰度，可能最为人熟知的例子是查找重复单词的正则表达式，如下面的代码所示：

```py
>>>pattern = re.compile(r"(\w+) **\1**")
>>>match = pattern.search(r"hello hello world")
>>>match.groups()
('hello',)
```

在这里，我们捕获了一个由一个或多个字母数字字符组成的组，然后模式尝试匹配一个空格，最后我们有`\1`反向引用。您可以在代码中看到它被突出显示，这意味着它必须与第一个组匹配的内容完全相同。

反向引用可以与前 99 个组一起使用。显然，随着组数的增加，阅读和维护正则表达式的任务会变得更加复杂。这是可以通过命名组来减少的，我们将在下一节中看到它们。但在那之前，我们还有很多关于反向引用的东西要学习。所以，让我们继续进行另一个操作，其中反向引用真的非常方便。回想一下之前的例子，其中我们有一个产品列表。现在，让我们尝试改变 ID 的顺序，这样我们就有了数据库中的 ID，一个破折号和国家代码：

```py
>>>pattern = re.compile(r"(\d+)-(\w+)")
>>>pattern.sub(**r"\2-\1"**, "1-a\n20-baer\n34-afcr")
'a-1\nbaer-20\nafcr-34'
```

就是这样。很简单，不是吗？请注意，我们还捕获了数据库中的 ID，所以我们以后可以使用它。通过突出显示的代码，我们在说，“用你匹配到的第二组、一个破折号和第一组来替换”。

与之前的例子一样，使用数字可能难以跟踪和维护。因此，让我们看看 Python 通过`re`模块提供的帮助。

# 命名组

还记得上一章中我们通过索引获取组的时候吗？

```py
>>>pattern = re.compile(r"(\w+) (\w+)")
>>>match = pattern.search("Hello⇢world")
>>>match.group(1)
  'Hello'
>>>match.group(2)
  'world'
```

我们刚刚学会了如何使用索引访问组来提取信息并将其用作反向引用。使用数字来引用组可能会很繁琐和令人困惑，最糟糕的是它不允许你给组赋予含义或上下文。这就是为什么我们有命名组。

想象一下一个正则表达式，其中有几个反向引用，比如说 10 个，然后你发现第三个是无效的，所以你从正则表达式中删除它。这意味着你必须更改从那个位置开始的每个反向引用的索引。为了解决这个问题，1997 年，Guido Van Rossum 为 Python 1.5 设计了命名组。这个功能被提供给了 Perl 进行交叉传播。

现在，它几乎可以在任何风格中找到。基本上它允许我们给组命名，这样我们可以在任何涉及组的操作中通过它们的名称来引用它们。

为了使用它，我们必须使用`(?P<name>pattern)`的语法，其中`P`来自于 Python 特定的扩展（正如你可以在 Guido 发送给 Perl 开发人员的电子邮件中所读到的那样[`markmail.org/message/oyezhwvefvotacc3`](http://markmail.org/message/oyezhwvefvotacc3)）

让我们看看它是如何在以下代码片段中与之前的例子一起工作的：

```py
>>> pattern = re.compile(r"(?P<first>\w+) (?P<second>\w+)")
>>> match = re.search("Hello world")
>>>match.group("first")
  'Hello'
>>>match.group("second")
  'world'
```

因此，反向引用现在使用起来更简单，更容易维护，正如下面的例子所示：

```py
>>>pattern = re.compile(r"(?P<country>\d+)-(?P<id>\w+)")
>>>pattern.sub(r"\g<id>-\g<country>", "1-a\n20-baer\n34-afcr")
'a-1\nbaer-20\nafcr-34'
```

正如我们在前面的例子中看到的，为了在`sub`操作中通过名称引用组，我们必须使用\`g<name>\`。

我们还可以在模式内部使用命名组，就像下面的例子中所示的那样：

```py
>>>pattern = re.compile(r"(?P<word>\w+) (?P=word)")
>>>match = pattern.search(r"hello hello world")
>>>match.groups()
('hello',)
```

这比使用数字更简单和更易读。

通过这些例子，我们使用了以下三种不同的方式来引用命名组：

| 使用 | 语法 |
| --- | --- |
| 在模式内 | (?P=name) |
| 在`sub`操作的`repl`字符串中 | \g<name> |
| 在`MatchObject`的任何操作中 | match.group('name') |

# 非捕获组

正如我们之前提到的，捕获内容并不是组的唯一用途。有时我们想要使用组，但并不想提取信息；交替是一个很好的例子。这就是为什么我们有一种方法可以创建不捕获的组。在本书中，我们一直在使用组来创建子表达式，就像下面的例子中所示的那样：

```py
>>>re.search("Españ(a|ol)", "Español")
<_sre.SRE_Match at 0x10e90b828>
>>>re.search("Españ(a|ol)", "Español").groups()
('ol',)
```

你可以看到，即使我们对组的内容不感兴趣，我们仍然捕获了一个组。所以，让我们尝试一下不捕获，但首先我们必须知道语法，它几乎与普通组的语法相同，`(?:pattern)`。如你所见，我们只是添加了`?:`。让我们看看下面的例子：

```py
>>>re.search("Españ(?:a|ol)", "Español")
<_sre.SRE_Match at 0x10e912648>
>>>re.search("Españ(?:a|ol)", "Español").groups()
()
```

使用新的语法后，我们拥有了与以前相同的功能，但现在我们节省了资源，正则表达式更容易维护。请注意，该组不能被引用。

## 原子组

它们是非捕获组的特殊情况；它们通常用于提高性能。它禁用回溯，因此您可以避免在模式中尝试每种可能性或路径都没有意义的情况。这个概念很难理解，所以请跟我一直看到本节的结束。

`re`模块不支持原子组。因此，为了看一个例子，我们将使用 regex 模块：[`pypi.python.org/pypi/regex`](https://pypi.python.org/pypi/regex)。

假设我们要寻找由一个或多个字母数字字符组成的 ID，后面跟着一个破折号和一个数字：

```py
>>>data = "aaaaabbbbbaaaaccccccdddddaaa"
>>>regex.match("(\w+)-\d",data)
```

让我们一步一步地看看这里发生了什么：

1.  正则表达式引擎匹配了第一个`a`。

1.  然后它匹配直到字符串的末尾的每个字符。

1.  它失败了，因为它找不到破折号。

1.  因此，引擎进行回溯，并尝试下一个`a`。

1.  再次开始相同的过程。

它尝试了每个字符。如果您考虑我们正在做的事情，一旦第一次失败，继续尝试就没有任何意义。这正是原子组的用处。例如：

```py
>>>regex.match("(?>\w+)-\d",data)
```

在这里，我们添加了`?>`，这表示一个原子组，因此一旦正则表达式引擎无法匹配`,`，它就不会继续尝试数据中的每个字符。

# 组的特殊情况

Python 为我们提供了一些形式的组，可以帮助我们修改正则表达式，甚至只有在匹配前一个组存在于匹配中时才匹配模式，比如`if`语句。

## 每组的标志

有一种方法可以应用我们在第二章*使用 Python 进行正则表达式*中看到的标志，使用一种特殊的分组形式：`(?iLmsux)`。

| Letter | Flag |
| --- | --- |
| **i** | re.IGNORECASE |
| **L** | re.LOCALE |
| **m** | re.MULTILINE |
| **s** | re.DOTALL |
| **u** | re.UNICODE |
| **x** | re.VERBOSE |

例如：

```py
>>>re.findall(r"(?u)\w+" ,ur"ñ")
[u'\xf1']
```

上面的例子与以下相同：

```py
>>>re.findall(r"\w+" ,ur"ñ", re.U)
[u'\xf1']
```

我们在上一章中多次看到了这些例子的作用。

请记住，标志适用于整个表达式。

## yes-pattern|no-pattern

这是组的一个非常有用的情况。它尝试在找到前一个的情况下匹配模式。另一方面，它不会在找不到前一个组的情况下尝试匹配模式。简而言之，它就像一个 if-else 语句。此操作的语法如下：

```py
(?(id/name)yes-pattern|no-pattern)
```

这个表达式的意思是：如果具有此 ID 的组已经匹配，那么在字符串的这一点，`yes-pattern`模式必须匹配。如果组尚未匹配，则`no-pattern`模式必须匹配。

让我们继续看看它是如何工作的。我们有一个产品列表，但在这种情况下，ID 可以用两种不同的方式制作：

+   国家代码（两位数字），一个破折号，三个或四个字母数字字符，一个破折号，和区号（2 位数字）。例如：`34-adrl-01`。

+   三个或四个字母数字字符。例如：`adrl`。

因此，当有国家代码时，我们需要匹配国家地区：

```py
>>>pattern = re.compile(r"(\d\d-)?(\w{3,4})(?(1)(-\d\d))")
>>>pattern.match("34-erte-22")
<_sre.SRE_Match at 0x10f68b7a0>
>>>pattern.search("erte")
<_sre.SRE_Match at 0x10f68b828>
```

正如您在前面的例子中所看到的，当我们有国家代码和区号时，就会有匹配。请注意，当有国家代码但没有区号时，就没有匹配：

```py
>>>pattern.match("34-erte")
None
```

`no-pattern`是用来做什么的？让我们在前面的例子中添加另一个约束：如果没有国家代码，字符串的末尾必须有一个名字：

+   国家代码（2 位数字），一个破折号，三个或四个字母数字字符，一个破折号，和区号（2 位数字）。例如：`34-adrl-01`

+   三个或四个字母数字字符，后面跟着三个或四个字符。例如：`adrl-sala`。

让我们看看它是如何运作的：

```py
>>>pattern = re.compile(r"(\d\d-)?(\w{3,4})-(?(1)(\d\d)|[a-z]{3,4})$")
>>>pattern.match("34-erte-22")
<_sre.SRE_Match at 0x10f6ee750>
```

如预期的那样，如果有国家代码和区号，就会有匹配。

```py
>>>pattern.match("34-erte")
None
```

在前面的例子中，我们确实有国家地区，但没有区号，因此没有匹配。

```py
>>>pattern.match("erte-abcd")
<_sre.SRE_Match at 0x10f6ee880>
```

最后，当没有国家地区时，必须有一个名字，所以我们有一个匹配。

请注意，`no-pattern`是可选的，因此在第一个例子中，我们省略了它。

# 重叠组

在第二章*使用 Python 进行正则表达式*中，我们看到了几个操作，其中有关重叠组的警告：例如，`findall`操作。这似乎让很多人感到困惑。因此，让我们尝试通过一个简单的例子来带来一些清晰度：

```py
>>>re.findall(r'(a|b)+', 'abaca')
['a', 'a']
```

这里发生了什么？为什么以下表达式给出了`'a'`和`'a'`而不是`'aba'`和`'a'`？

让我们一步一步地看看解决方案：

![重叠组](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_03_01.jpg)

重叠组匹配过程

正如我们在前面的图中看到的，字符`aba`被匹配，但捕获的组只由`a`组成。这是因为即使我们的正则表达式将每个字符分组，它仍然保留最后的`a`。请记住这一点，因为这是理解它如何工作的关键。停下来思考一下，我们要求正则表达式引擎捕获由`a`或`b`组成的所有组，但只对一个字符进行分组，这就是关键。那么，如何捕获由多个`'a'`或`'b'`组成的组，而且顺序无关呢？以下表达式可以实现：

```py
>>>re.findall(r'((?:a|b)+)', 'abbaca')
   ['abba', 'a']
```

我们要求正则表达式引擎捕获由子表达式（`a|b`）组成的每个组，而不是仅对一个字符进行分组。

最后一件事——如果我们想要用`findall`获得由`a`或`b`组成的每个组，我们可以写下这个简单的表达式：

```py
>>>re.findall(r'(a|b)', 'abaca')
   ['a', 'b', 'a', 'a']
```

在这种情况下，我们要求正则表达式引擎捕获由`a`或`b`组成的组。由于我们使用了`findall`，我们得到了每个匹配的模式，所以我们得到了四个组。

### 提示

**经验法则**

最好尽可能简化正则表达式。因此，你应该从最简单的表达式开始，然后逐步构建更复杂的表达式，而不是相反。

# 总结

不要让本章的简单性愚弄你，我们在本章学到的东西将在你日常使用正则表达式的工作中非常有用，并且会给你很大的优势。

让我们总结一下到目前为止我们学到的东西。首先，我们看到了当我们需要对表达式的某些部分应用量词时，组如何帮助我们。

我们还学会了如何再次在模式中使用捕获的组，甚至在`sub`操作中使用替换字符串，这要归功于**反向引用**。

在本章中，我们还查看了命名组，这是一种改进正则表达式可读性和未来维护的工具。

后来，我们学会了只有在先前存在一个组的情况下才匹配子表达式，或者另一方面，只有在先前不存在一个组的情况下才匹配它。

现在我们知道如何使用组，是时候学习一个与组非常接近的更复杂的主题了；四处看看吧！


# 第四章：环视

到目前为止，我们已经学习了在丢弃字符的同时匹配字符的不同机制。已经匹配的字符不能再次比较，匹配任何即将到来的字符的唯一方法是丢弃它。

这些字符指示位置而不是实际内容。例如，插入符号(`^`)表示行的开头，或者美元符号(`$`)表示行的结尾。它们只是确保输入中的位置正确，而不实际消耗或匹配任何字符。

更强大的零宽断言是**环视**，这是一种机制，可以将先前的某个值（**向后查找**）或后续的某个值（**向前查找**）与当前位置匹配。它们有效地进行断言而不消耗字符；它们只是返回匹配的正面或负面结果。

环视机制可能是正则表达式中最不为人知，同时也是最强大的技术。这种机制允许我们创建强大的正则表达式，否则无法编写，要么是因为它代表的复杂性，要么是因为正则表达式在没有环视的情况下的技术限制。

在本章中，我们将学习如何使用 Python 正则表达式来利用环视机制。我们将了解如何应用它们，它们在幕后是如何工作的，以及 Python 正则表达式模块对我们施加的一些限制。

正向环视和负向环视都可以细分为另外两种类型：正向和负向：

+   **正向环视**：这种机制表示为一个由问号和等号`?=`组成的表达式，放在括号块内。例如，`(?=regex)`将匹配传递的正则表达式*是否*与即将到来的输入匹配。

+   **负向环视**：这种机制被指定为一个由问号和感叹号`?!`组成的表达式，放在括号块内。例如，`(?!regex)`将匹配传递的正则表达式*是否不*与即将到来的输入匹配。

+   **正向环视**：这种机制表示为一个由问号、小于号和等号`?<=`组成的表达式，放在括号块内。例如，`(?<=regex)`将匹配传递的正则表达式*是否*与先前的输入匹配。

+   **负向环视**：这种机制表示为一个由问号、小于号和感叹号`?<!`组成的表达式，放在括号块内。例如，`(?<!regex)`将匹配传递的正则表达式*是否不*与先前的输入匹配。

让我们开始期待下一节。

# 向前查看

我们将要学习的第一种环视机制是向前环视机制。它试图匹配作为参数传递的子表达式。这两种环视操作的零宽度特性使它们变得复杂和难以理解。

正如我们从前一节所知，它表示为一个由问号和等号`?=`组成的表达式，放在括号块内：`(?=regex)`。

让我们通过比较两个类似的正则表达式的结果来开始解决这个问题。我们可以回忆一下，在第一章中，*介绍正则表达式*，我们将表达式`/fox/`与短语`The quick brown fox jumps over the lazy dog`匹配。让我们也将表达式`/(?=fox)/`应用到相同的输入中：

```py
>>>pattern = re.compile(r'fox')
>>>result = pattern.search("The quick brown fox jumps over the lazy dog")
>>>print result.start(), result.end()
16 19
```

我们刚刚在输入字符串中搜索了字面上的`fox`，正如预期的那样，我们在索引`16`和`19`之间找到了它。让我们看一下正向环视机制的下一个例子：

```py
>>>pattern = re.compile(r'(?=fox)')
>>>result = pattern.search("The quick brown fox jumps over the lazy dog")
>>>print result.start(), result.end()
16 16
```

这次我们应用了表达式`/(?=fox)/`。结果只是一个位置在索引`16`（起始和结束点都指向相同的索引）。这是因为向前查找不会消耗字符，因此可以用来过滤表达式应该匹配的位置。但它不会定义结果的内容。我们可以在下图中直观地比较这两个表达式：

![向前查找](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_04_01.jpg)

正常匹配和向前查找的比较

让我们再次使用这个特性，尝试匹配任何后面跟着逗号字符（`,`）的单词，使用以下正则表达式`/\w+(?=,)/`和文本`They were three: Felix, Victor, and Carlos`：

```py
>>>pattern = re.compile(r'\w+(?=,)')
>>>pattern.findall("They were three: Felix, Victor, and Carlos.")
['Felix', 'Victor']
```

我们创建了一个正则表达式，接受任何重复的字母数字字符，后面跟着一个逗号字符，这不会作为结果的一部分使用。因此，只有`Felix`和`Victor`是结果的一部分，因为`Carlos`的名字后面没有逗号。

这与我们在本章中使用的正则表达式有多大不同？让我们通过将`/\w+,/`应用于相同的文本来比较结果：

```py
>>>pattern = re.compile(r'\w+,')
>>>pattern.findall("They were three: Felix, Victor, and Carlos.")
['Felix,', 'Victor,']
```

通过前面的正则表达式，我们要求正则表达式引擎接受任何重复的字母数字字符，后面跟着一个逗号字符。因此，字母数字字符*和逗号字符*将被返回，正如我们在列表中看到的。

值得注意的是，向前查找机制是另一个可以利用正则表达式所有功能的子表达式（这在向后查找机制中并非如此，我们稍后会发现）。因此，我们可以使用到目前为止学到的所有构造，如交替：

```py
>>>pattern = re.compile(r'\w+(?=,|\.)')
>>>pattern.findall("They were three: Felix, Victor, and Carlos.")
['Felix', 'Victor', 'Carlos']
```

在前面的例子中，我们使用了交替（即使我们可以使用其他更简单的技术，如字符集）来接受任何重复的字母数字字符，后面跟着一个逗号或点字符，这不会作为结果的一部分使用。

## 负向查找

负向查找机制具有与向前查找相同的性质，但有一个显著的区别：只有子表达式不匹配时，结果才有效。

它表示为一个由问号和感叹号`?!`组成的表达式，放在括号块内：`(?!regex)`。

当我们想要表达不应该发生的情况时，这是很有用的。例如，要找到任何不是`John Smith`的名字`John`，我们可以这样做：

```py
>>>pattern = re.compile(r'John(?!\sSmith)')                                    >>> result = pattern.finditer("I would rather go out with **John** McLane than with John Smith or **John** Bon Jovi")
>>>for i in result:
...print i.start(), i.end()
...
27 31
63 67
```

在前面的例子中，我们通过消耗这五个字符来寻找`John`，然后向前查找一个空格字符，后面跟着单词`Smith`。如果匹配成功，匹配结果将只包含`John`的起始和结束位置。在这种情况下，`John McLane`的位置是`27`-`31`，`John Bon Jovi`的位置是`63`-`67`。

现在，我们能够利用更基本的向前查找形式：正向和负向查找。让我们学习如何在替换和分组中充分利用它。

# 向前查找和替换

向前查找操作的零宽度特性在替换中特别有用。由于它们，我们能够执行在其他情况下会非常复杂的转换。

向前查找和替换的一个典型例子是将仅由数字字符组成的数字（例如 1234567890）转换为逗号分隔的数字，即 1,234,567,890。

为了编写这个正则表达式，我们需要一个策略来跟随。我们想要做的是将数字分组成三个一组，然后用相同的组加上一个逗号字符来替换它们。

我们可以从一个几乎天真的方法开始，使用以下突出显示的正则表达式：

```py
>>>pattern = re.compile(r'**\d{1,3}**')
>>>pattern.findall("The number is: 12345567890")
['123', '455', '678', '90']
```

我们在这次尝试中失败了。我们实际上是在三个数字的块中进行分组，但应该从右到左进行。我们需要不同的方法。让我们尝试找到一个、两个或三个数字，这些数字必须后面跟着任意数量的三位数字块，直到我们找到一个不是数字的东西。

这将对我们的数字产生以下影响。当尝试找到一个、两个或三个数字时，正则表达式将开始只取一个，这将是数字`1`。然后，它将尝试捕捉恰好三个数字的块，例如 234、567、890，直到找到一个非数字。这是输入的结尾。

如果我们用正则表达式来表达我们刚刚用普通英语解释的内容，我们将得到以下结果：

```py
/\d{1,3}(?=(\d{3})+(?!\d))/
```

| 元素 | 描述 |
| --- | --- |

|

```py
\d
```

| 这匹配一个十进制字符 |
| --- |

|

```py
{1,3}
```

| 这表示匹配重复一到三次 |
| --- |

|

```py
(?=
```

| 这表示该字符后面跟着（但不消耗）这个表达式 |
| --- |

|

```py
(
```

| 这表示一个组 |
| --- |

|

```py
\d
```

| 这表示有一组十进制字符 |
| --- |

|

```py
\s
```

| 这表示匹配重复三次 |
| --- |

|

```py
)
```

|   |
| --- |

|

```py
+
```

| 这表示十进制字符应该出现一次或多次 |
| --- |

|

```py
(?!
```

| 这表示匹配不是后面跟着（但不消耗）下一个表达式定义的内容 |
| --- |

|

```py
\d
```

| 这表示一个十进制字符 |
| --- |

|

```py
))
```

|   |
| --- |

让我们在 Python 的控制台中再次尝试这个新的正则表达式：

```py
>>>pattern = re.compile(r'\d{1,3}(?=(\d{3})+(?!\d))')
>>>results = pattern.finditer('1234567890')
>>>for result in results:
...    print result.start(), result.end()
...
0 1
1 4
4 7
```

这一次，我们可以看到我们正在使用正确的方法，因为我们刚刚确定了正确的块：`1`、`234`、`567`和`890`。

现在，我们只需要使用替换来替换我们找到的每个匹配项，使其成为相同的匹配结果加上逗号字符。我们已经知道如何使用替换，因为我们在第二章中学习过，*使用 Python 进行正则表达式*，所以让我们把它付诸实践：

```py
>>>pattern = re.compile(r'\d{1,3}(?=(\d{3})+(?!\d))')
>>>pattern.sub(r'\g<0>,', "1234567890")
'1,234,567,890'
```

Et voila！我们刚刚将一个未格式化的数字转换成了一个带有千位分隔符的美丽数字。

我们刚刚学会了两种技术，可以预见未来会发生什么。我们还研究了它们在替换中的用法。现在，让我们回头看看我们留下的东西**向后看**。

# 向后看

我们可以安全地将向后看定义为与向前看相反的操作。它试图匹配作为参数传递的子表达式之后的内容。它也具有零宽度的特性，因此不会成为结果的一部分。

它表示为一个表达式，前面有一个问号、一个小于号和一个等号，`?<=`，在一个括号块内：`(?<=regex)`。

例如，我们可以在类似于我们在负向向前看中使用的示例中使用它，只找到名为`John McLane`的人的姓。为了实现这一点，我们可以写一个类似下面的向后看：

```py
>>>pattern = re.compile(r'(?<=John\s)McLane')
>>>result = pattern.finditer("I would rather go out with John **McLane** than with John Smith or John Bon Jovi")
>>>for i in result:
...    print i.start(), i.end()
...
32 38
```

通过前面的向后看，我们要求正则表达式引擎只匹配那些前面跟着`John`和一个空格的位置，然后消耗`McLane`作为结果。

在 Python 的`re`模块中，然而，向前看和向后看的实现之间有一个根本的区别。由于一些根深蒂固的技术原因，向后看机制只能匹配固定宽度的模式。如果需要在向后看中使用可变宽度模式，则可以使用[`pypi.python.org/pypi/regex`](https://pypi.python.org/pypi/regex)中的正则表达式模块，而不是标准的 Python `re`模块。

固定宽度模式不包含我们在第一章中学习的量词这样的可变长度匹配器，*介绍正则表达式*。其他可变长度构造，如反向引用也是不允许的。选择是允许的，但只有在备选项具有相同的长度时才允许。同样，这些限制在前述的正则表达式模块中是不存在的。

让我们看看如果我们在反向引用中使用不同长度的选择会发生什么：

```py
>>>pattern = re.compile(r'(?<=(John|Jonathan)\s)McLane')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/re.py", line 190, in compile
return _compile(pattern, flags)
  File "/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/re.py", line 242, in _compile
raise error, v # invalid expression
sre_constants.error: **look-behind requires fixed-width pattern

```

我们有一个例外，因为后面的查找需要一个固定宽度的模式。如果我们尝试应用量词或其他可变长度的结构，我们将得到类似的结果。

现在我们已经学会了不消耗字符的匹配前后不匹配的不同技术和我们可能遇到的不同限制，我们可以尝试编写另一个示例，结合我们学习过的一些机制来解决一个现实世界的问题。

假设我们想要提取出推文中存在的任何 Twitter 用户名，以创建一个自动情绪检测系统。为了编写一个正则表达式来提取它们，我们应该首先确定 Twitter 用户名是如何表示的。如果我们浏览 Twitter 的网站[`support.twitter.com/articles/101299-why-can-t-i-register-certain-usernames`](https://support.twitter.com/articles/101299-why-can-t-i-register-certain-usernames)，我们可能会找到以下描述：

> 用户名只能包含字母数字字符（A-Z 的字母，0-9 的数字），除了下划线，如上所述。检查一下，确保你想要的用户名不包含任何符号、破折号或空格。

对于我们的开发测试，我们将使用这条 Packt Publishing 推文：

![后视](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_04_02.jpg)

我们应该首先构建一个包含所有可能用于 Twitter 用户名的字符的字符集。这可能是任何字母数字字符，后面跟着下划线字符，就像我们刚才在前面的 Twitter 支持文章中发现的那样。因此，我们可以构建一个类似以下的字符集：

```py
[\w_]
```

这将表示我们想要从用户名中提取的所有部分。然后，我们需要在用户名前加上一个单词边界和 at 符号（`@`）来定位用户名：

```py
/\B@[\w_]+/
```

使用单词边界的原因是我们不想与电子邮件等混淆。我们只寻找紧随行首或单词边界之后，然后跟着@符号，然后是一些字母数字或下划线字符的文本。示例如下：

+   `@vromer0`是一个有效的用户名

+   `iam@vromer0`不是一个有效的用户名，因为它应该以@符号开头

+   `@vromero.org`不是一个有效的用户名，因为它包含一个无效字符

如果我们使用目前的正则表达式，我们将得到以下结果：

```py
>>>pattern = re.compile(r'\B@[\w_]+') 
>>>pattern.findall("Know your Big Data = 5 for $50 on eBooks and 40% off all eBooks until Friday #bigdata #hadoop @HadoopNews packtpub.com/bigdataoffers")
['@HadoopNews']
```

我们只想匹配用户名，而不包括前面的@符号。在这一点上，后视机制变得有用。我们可以在后视子表达式中包含单词边界和@符号，这样它们就不会成为匹配结果的一部分：

```py
>>>pattern = re.compile(r'(?<=\B@)[\w_]+')
>>>pattern.findall("Know your Big Data = 5 for $50 on eBooks and 40% off all eBooks until Friday #bigdata #hadoop @HadoopNews packtpub.com/bigdataoffers")
['HadoopNews']
```

现在我们已经实现了我们的目标。

## 负向后视

负向后视机制具有与主要后视机制完全相同的性质，但只有在传递的子表达式不匹配时才会得到有效结果。

它表示为一个表达式，前面有一个问号、一个小于号和一个感叹号，`?<!`，在括号块内：`(?<!regex)`。

值得记住的是，负向后视不仅具有前视机制的大部分特征，而且还具有相同的限制。负向后视机制只能匹配固定宽度的模式。这与我们在前一节中学习的原因和影响是一样的。

我们可以通过尝试匹配任何姓氏为`Doe`但不叫`John`的人来实践这一点，使用这样的正则表达式：`/(?<!John\s)Doe/`。如果我们在 Python 的控制台中使用它，我们将得到以下结果：

```py
>>>pattern = re.compile(r'(?<!John\s)Doe')
>>>results = pattern.finditer("John Doe, Calvin **Doe**, Hobbes **Doe**")
>>>for result in results:
...   print result.start(), result.end()
...
17 20
29 32
```

# 环视和分组

在组内使用环视结构的另一个有益的用途。通常，当使用组时，必须在组内匹配并返回非常具体的结果。由于我们不希望在组内添加不必要的信息，因此在其他潜在选项中，我们可以利用环视作为一个有利的解决方案。

假设我们需要获取一个逗号分隔的值，值的第一部分是一个名称，而第二部分是一个值。格式类似于这样：

```py
INFO 2013-09-17 12:13:44,487 authentication failed
```

正如我们在第三章中学到的*分组*，我们可以轻松地编写一个表达式，以获取以下两个值：

```py
/\w+\s[\d-]+\s[\d:,]+\s(.*\sfailed)/
```

然而，我们只想在失败不是认证失败时进行匹配。我们可以通过添加负向后行来实现这一点。它看起来像这样：

```py
/\w+\s[\d-]+\s[\d:,]+\s(.*(?<!authentication\s)failed)/
```

一旦我们将其放入 Python 的控制台，我们将得到以下输出：

```py
>>>pattern = re.compile(r'\w+\s[\d-]+\s[\d:,]+\s(.*(?<!authentication\s)failed)')
>>>pattern.findall("INFO 2013-09-17 12:13:44,487 authentication failed")
[]
>>>pattern.findall("INFO 2013-09-17 12:13:44,487 something else failed")
['something else failed']
```

# 总结

在本章中，我们学习了零宽断言的概念，以及它如何在不干扰结果内容的情况下在文本中找到确切的内容。

我们还学习了如何利用四种类型的环视机制：正向先行断言，负向先行断言，正向后行断言和负向后行断言。

我们还特别关注了两种具有可变断言的后行环视的限制。

通过这样，我们结束了对正则表达式基本和高级技术的探讨。现在，我们准备在下一章节中专注于性能调优。


# 第五章：正则表达式的性能

到目前为止，我们担心学习如何利用一个功能或获得一个结果，而不太关心过程的速度。我们的唯一目标是正确性和可读性。

在本章中，我们将转向一个完全不同的关注点——性能。然而，我们会发现，通常性能的提高会导致可读性的降低。当我们修改某些东西以使其更快时，我们可能正在使机器更容易理解，因此，我们可能正在牺牲人类的可读性。

1974 年 12 月 4 日，著名书籍《计算机程序设计艺术》的作者唐纳德·克努斯写了一篇名为“结构化编程”的论文，其中包含了`go-to`语句。这个著名的引用摘自这篇论文：

> “程序员们浪费了大量时间思考或担心程序中非关键部分的速度，而这些对效率的努力实际上在调试和维护时产生了很大的负面影响。我们应该忘记小的效率，大约 97%的时间：过早的优化是万恶之源。然而，我们不应该放弃在关键的 3%中的机会。”

也就是说，我们应该谨慎考虑我们要优化什么。也许，对于用于验证电子邮件地址的正则表达式，我们应该更关注可读性而不是性能。另一方面，如果我们正在编写一个用于批处理大型历史文件的正则表达式，我们应该更关注性能。

最常用的优化方法是先编写，然后测量，然后优化关键的 3%。因此，在本章中，我们首先要学习如何测量和分析正则表达式，然后再进行优化技术。

# 使用 Python 对正则表达式进行基准测试

为了对我们的正则表达式进行基准测试，我们将测量正则表达式执行所需的时间。重要的是要用不同的输入来测试它们，因为对于小输入，几乎每个正则表达式都足够快。然而，对于更长的输入，情况可能完全不同，正如我们将在*回溯*部分中看到的那样。

首先，我们将创建一个小函数来帮助我们完成这个任务：

```py
>>> from time import clock as now
>>> def test(f, *args, **kargs):
        start = now()
        f(*args, **kargs)
        print "The function %s lasted: %f" %(f.__name__, now() - start)
```

因此，我们可以使用以下代码测试正则表达式：

```py
>>> def alternation(text):
       pat = re.compile('spa(in|niard)')
       pat.search(text)
>>> test(alternation, "spain")
The function alternation lasted: 0.000009
```

Python 自带了一个内置的分析器[`docs.python.org/2/library/profile.html`](http://docs.python.org/2/library/profile.html)，我们也可以用它来测量时间和调用次数等：

```py
>>> import cProfile
>>> cProfile.run("alternation('spaniard')")
```

您可以在以下截图中看到输出：

![使用 Python 对正则表达式进行基准测试](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_05_01.jpg)

分析输出

让我们看看另一种有用的技术，当你想要查看正则表达式下的情况时，这将会有所帮助。这是我们在第二章中已经见过的东西，*使用 Python 进行正则表达式*，标志 DEBUG。回想一下，它为我们提供了有关模式如何编译的信息。例如：

```py
>>> re.compile('(\w+\d+)+-\d\d', re.DEBUG)
max_repeat 1 4294967295
  subpattern 1
    max_repeat 1 4294967295
      in
        category category_word
    max_repeat 1 4294967295
      in
        category category_digit
literal 45
in
  category category_digit
in
  category category_digit
```

在这里，我们可以看到三个`max_repeat`条件从`1`到`4294967295`，其中两个嵌套在另一个`max_repeat`中。把它们想象成嵌套循环，你可能会觉得这是一种不好的迹象。事实上，这将导致**灾难性的回溯**，这是我们稍后会看到的。

# RegexBuddy 工具

在编写正则表达式时，有许多不同的工具可用于提高生产力，其中**RegexBuddy**([`www.regexbuddy.com/`](http://www.regexbuddy.com/))由 Just Great Software Co. Ltd.开发的工具非常出色。

Just Great Software 的幕后推手是 Jan Goyvaerts，也是**Regular-Expressions.info**([`www.regular-expressions.info/`](http://www.regular-expressions.info/))的幕后人物，这是互联网上最著名的正则表达式参考之一。

使用 RegexBuddy，我们可以使用可视化界面构建、测试和调试正则表达式。调试功能几乎是独一无二的，并提供了一个很好的机制来理解正则表达式引擎在幕后的工作方式。在下面的截图中，我们可以看到 RegexBuddy 调试正则表达式的执行：

![RegexBuddy 工具](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_05_02.jpg)

RegexBuddy 调试正则表达式

它确实具有其他功能，例如常用正则表达式库和不同编程环境的代码生成器。

尽管它有一些缺点，但它的许可证是专有的，唯一可用的构建是 Windows。然而，可以使用**wine 模拟器**在 Linux 上执行。

# 理解 Python 正则表达式引擎

`re`模块使用回溯正则表达式引擎；尽管在*Jeffrey E. F. Friedl*的著名书籍*《精通正则表达式》*中，它被归类为**非确定性有限自动机**（**NFA**）类型。此外，根据*Tim Peters*（[`mail.python.org/pipermail/tutor/2006-January/044335.html`](https://mail.python.org/pipermail/tutor/2006-January/044335.html)），该模块并非纯粹的 NFA。

这些是算法的最常见特征：

+   它支持“懒惰量词”，如`*?`、`+?`和`??`。

+   它匹配第一个匹配项，即使在字符串中有更长的匹配项。

```py
>>>re.search("engineer|engineering", "engineering").group()'engineer'
```

这也意味着顺序很重要。

+   该算法一次只跟踪一个转换，这意味着引擎一次只检查一个字符。

+   支持反向引用和捕获括号。

+   **回溯**是记住上次成功位置的能力，以便在需要时可以返回并重试

+   在最坏的情况下，复杂度是指数级的 O(*C^n*)。我们稍后会在*回溯*中看到这一点。

## 回溯

正如我们之前提到的，回溯允许返回并重复正则表达式的不同路径。它通过记住上次成功的位置来实现。这适用于交替和量词。让我们看一个例子：

![回溯](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/3156OS_05_03.jpg)

回溯

正如你在上图中看到的，正则表达式引擎尝试一次匹配一个字符，直到失败，然后从下一个可以重试的路径开始重新开始。

在图中使用的正则表达式是如何构建正则表达式的重要性的完美例子。在这种情况下，表达式可以重建为`spa(in|niard)`，这样正则表达式引擎就不必返回到字符串的开头来重试第二个选择。

这导致了一种称为灾难性回溯的东西；这是回溯的一个众所周知的问题，它可能会给你带来从缓慢的正则表达式到堆栈溢出的崩溃等多种问题。

在前面的例子中，你可以看到行为不仅随着输入而增长，而且随着正则表达式中不同的路径而增长，因此算法可能是指数级的 O(*C^n*)。有了这个想法，就很容易理解为什么我们最终可能会遇到堆栈溢出的问题。当正则表达式无法匹配字符串时，问题就出现了。让我们用之前见过的技术来对正则表达式进行基准测试，以便更好地理解问题。

首先，让我们尝试一个简单的正则表达式：

```py
>>> def catastrophic(n):
        print "Testing with %d characters" %n
        pat = re.compile('(a+)+c')
text = "%s" %('a' * n)
        pat.search(text)
```

正如你所看到的，我们试图匹配的文本总是会失败，因为末尾没有`c`。让我们用不同的输入进行测试：

```py
>>> for n in range(20, 30):
        test(catastrophic, n)
Testing with 20 characters
The function catastrophic lasted: 0.130457
Testing with 21 characters
The function catastrophic lasted: 0.245125
……
The function catastrophic lasted: 14.828221
Testing with 28 characters
The function catastrophic lasted: 29.830929
Testing with 29 characters
The function catastrophic lasted: 61.110949
```

这个正则表达式的行为看起来像是二次的。但是为什么？这里发生了什么？问题在于`(a+)`是贪婪的，所以它试图尽可能多地获取`a`字符。之后，它无法匹配`c`，也就是说，它回溯到第二个`a`，并继续消耗`a`字符，直到无法匹配`c`。然后，它再次尝试整个过程（回溯），从第二个`a`字符开始。

让我们看另一个例子，这次是指数级的行为：

```py
>>> def catastrophic(n):
        print "Testing with %d characters" %n
        pat = re.compile('(x+)+(b+)+c')
        **text = 'x' * n
        **text += 'b' * n
        pat.search(text)
>>> for n in range(12, 18):
        test(catastrophic, n)
Testing with 12 characters
The function catastrophic lasted: 1.035162
Testing with 13 characters
The function catastrophic lasted: 4.084714
Testing with 14 characters
The function catastrophic lasted: 16.319145
Testing with 15 characters
The function catastrophic lasted: 65.855182
Testing with 16 characters
The function catastrophic lasted: 276.941307
```

正如你所看到的，这种行为是指数级的，可能导致灾难性的情况。最后，让我们看看当正则表达式有匹配时会发生什么：

```py
>>> def non_catastrophic(n):
        print "Testing with %d characters" %n
        pat = re.compile('(x+)+(b+)+c')
        **text = 'x' * n
        **text += 'b' * n
        **text += 'c'
        pat.search(text)
>>> for n in range(12, 18):
        test(non_catastrophic, n)
Testing with 10 characters
The function catastrophic lasted: 0.000029
……
Testing with 19 characters
The function catastrophic lasted: 0.000012
```

# 优化建议

在接下来的章节中，我们将找到一些可以应用于改进正则表达式的建议。

最好的工具始终是常识，即使在遵循这些建议时，也需要使用常识。必须理解建议何时适用，何时不适用。例如，建议“不要贪婪”并不适用于所有情况。

## 重用编译模式

我们在第二章中学到，要使用正则表达式，我们必须将其从字符串表示形式转换为编译形式，即`RegexObject`。

这种编译需要一些时间。如果我们使用模块操作的其余部分而不是使用编译函数来避免创建`RegexObject`，我们应该明白编译仍然会执行，并且一些编译的`RegexObject`会自动缓存。

然而，当我们进行编译时，缓存不会支持我们。每次编译执行都会消耗一定的时间，对于单次执行来说可能可以忽略不计，但如果执行多次则肯定是相关的。

让我们看看在以下示例中重用和不重用编译模式的区别：

```py
>>> def **dontreuse**():
        pattern = re.compile(r'\bfoo\b')
        pattern.match("foo bar")

>>> def callonethousandtimes():
        for _ in range(1000):
            dontreuse()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.001965

>>> pattern = re.compile(r'\bfoo\b')
>>> def **reuse**():
        pattern.match("foo bar")

>>> def callonethousandtimes():
        for _ in range(1000):
            reuse()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.000633
>>>
```

## 在交替中提取公共部分

在正则表达式中，交替总是存在性能风险。在 Python 中使用 NFA 实现时，我们应该将任何公共部分提取到交替之外。

例如，如果我们有`/(Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)`World|Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)`Continent|Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)`Country,)/`，我们可以很容易地用以下表达式提取`Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)：`/Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)`(World|Continent|Country)/`。这将使我们的引擎只检查一次`Hello`![在交替中提取公共部分](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/ms-py-re/img/inlinemedia.jpg)，而不会回头重新检查每种可能性。在下面的示例中，我们可以看到执行上的差异：

```py
>>> pattern = re.compile(r'/(Hello\sWorld|Hello\sContinent|Hello\sCountry)')
>>> def **nonoptimized**():
         pattern.match("Hello\sCountry")

>>> def callonethousandtimes():
         for _ in range(1000):
             nonoptimized()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.000645

>>> pattern = re.compile(r'/Hello\s(World|Continent|Country)')
>>> def **optimized**():
         pattern.match("Hello\sCountry")

>>> def callonethousandtimes():
         for _ in range(1000):
             optimized()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.000543
>>>
```

## 交替的快捷方式

在交替中的顺序很重要，交替中的每个不同选项都将逐个检查，从左到右。这可以用来提高性能。

如果我们将更有可能的选项放在交替的开头，更多的检查将更早地标记交替为匹配。

例如，我们知道汽车的常见颜色是白色和黑色。如果我们要编写一个接受一些颜色的正则表达式，我们应该将白色和黑色放在前面，因为这些更有可能出现。我们可以将正则表达式写成这样`/(white|black|red|blue|green)/`。

对于其余的元素，如果它们出现的几率完全相同，将较短的放在较长的前面可能是有利的：

```py
>>> pattern = re.compile(r'(white|black|red|blue|green)')
>>> def **optimized**():
         pattern.match("white")

>>> def callonethousandtimes():
         for _ in range(1000):
             optimized()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.000667
>>>

>>> pattern = re.compile(r'(green|blue|red|black|white)')
>>> def **nonoptimized**():
         pattern.match("white")

>>> def callonethousandtimes():
         for _ in range(1000):
             nonoptimized()

>>> test(callonethousandtimes)
The function callonethousandtimes lasted: 0.000862
>>>
```

## 在适当的时候使用非捕获组

捕获组将为表达式中定义的每个组消耗一些时间。这个时间并不是很重要，但如果我们多次执行正则表达式，它仍然是相关的。

有时，我们使用组，但可能对结果不感兴趣，例如在使用交替时。如果是这种情况，我们可以通过将该组标记为非捕获来节省引擎的一些执行时间，例如`(?:person|company)`。

## 具体化

当我们定义的模式非常具体时，引擎可以在实际模式匹配之前帮助我们执行快速的完整性检查。

例如，如果我们将表达式`/\w{15}/`传递给引擎，以匹配文本`hello`，引擎可能决定检查输入字符串是否实际上至少有 15 个字符长，而不是匹配表达式。

## 不要贪心

我们在第一章*介绍正则表达式*中学习了量词，并了解了贪婪和勉强量词之间的区别。我们还发现量词默认是贪婪的。

这在性能方面意味着什么？这意味着引擎将始终尝试尽可能多地捕获字符，然后逐步缩小范围，直到匹配完成。如果匹配通常很短，这可能使正则表达式变慢。然而，请记住，这仅适用于匹配通常很短的情况。

# 总结

在这最后一章中，我们开始学习优化的相关性，以及为什么我们应该避免过早的优化。然后，我们深入了解了通过学习不同的机制来测量正则表达式的执行时间。后来，我们了解了 RegexBuddy 工具，它可以帮助我们了解引擎是如何工作的，并帮助我们找出性能问题。

后来，我们了解了如何看到引擎在幕后的工作。我们学习了一些引擎设计的理论，以及如何容易陷入常见的陷阱——灾难性的回溯。

最后，我们回顾了不同的一般建议，以改善我们的正则表达式的性能。
