# C++ 软件架构（四）

> 原文：[`zh.annas-archive.org/md5/FF4E2693BC25818CA0990A2CB63D13B8`](https://zh.annas-archive.org/md5/FF4E2693BC25818CA0990A2CB63D13B8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：代码和部署中的安全性

在建立适当的测试之后，有必要进行安全审计，以确保我们的应用程序不会被用于恶意目的。本章描述了如何评估代码库的安全性，包括内部开发的软件和第三方模块。它还将展示如何在代码级别和操作系统级别改进现有软件。

您将学习如何在每个级别上设计重点放在安全性上的应用程序，从代码开始，通过依赖关系、架构和部署。

本章将涵盖以下主题：

+   检查代码安全性

+   检查依赖项是否安全

+   加固您的代码

+   加固您的环境

# 技术要求

本章中使用的一些示例需要具有以下最低版本的编译器：

+   GCC 10+

+   Clang 3.1+

本章中的代码已经放在 GitHub 上[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter10`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter10)。

# 检查代码安全性

在本章中，我们提供了有关如何检查您的代码、依赖项和环境是否存在潜在威胁的信息。但请记住，遵循本章中概述的每个步骤不一定会保护您免受所有可能的问题。我们的目标是向您展示一些可能的危险以及处理它们的方法。鉴于此，您应始终意识到系统的安全性，并使审计成为例行事件。

在互联网变得无处不在之前，软件作者并不太关心他们设计的安全性。毕竟，如果用户提供了格式不正确的数据，用户最多只能使自己的计算机崩溃。为了利用软件漏洞访问受保护的数据，攻击者必须获得物理访问权限到保存数据的机器。

即使是设计用于网络内部使用的软件，安全性也经常被忽视。以**超文本传输协议**（**HTTP**）为例。尽管它允许对某些资产进行密码保护，但所有数据都是以明文传输的。这意味着在同一网络上的每个人都可以窃听正在传输的数据。

今天，我们应该从设计的最初阶段就开始重视安全，并在软件开发、运营和维护的每个阶段都牢记安全性。我们每天生产的大部分软件都意味着以某种方式与其他现有系统连接。

通过省略安全措施，我们不仅使自己暴露于潜在的攻击、数据泄漏和最终诉讼的风险中，还使我们的合作伙伴暴露于潜在的攻击、数据泄漏和最终诉讼的风险中。请记住，未能保护个人数据可能会导致数百万美元的罚款。

## 注重安全的设计

我们如何为安全性设计架构？这样做的最佳方式是像潜在的攻击者一样思考。有许多方法可以打开一个盒子，但通常，您会寻找不同元素连接的裂缝。（在盒子的情况下，这可能是盒子的盖子和底部之间。）

在软件架构中，元素之间的连接称为接口。由于它们的主要作用是与外部世界进行交互，它们是整个系统中最容易受到攻击的部分。确保您的接口受到保护、直观和稳健将解决软件可能被破坏的最明显的方式。

### 使接口易于使用且难以滥用

为了设计接口既易于使用又难以滥用，考虑以下练习。想象一下你是接口的客户。您希望实现一个使用您的支付网关的电子商务商店，或者您希望实现一个连接本书中始终使用的示例系统的客户 API 的 VR 应用程序。

作为关于接口设计的一般规则，避免以下特征：

+   传递给函数/方法的参数太多

+   参数名称模糊

+   使用输出参数

+   参数取决于其他参数

为什么这些特征被认为是有问题的？

+   第一个特征不仅使参数的含义难以记忆，而且使参数的顺序也难以记忆。这可能导致使用错误，进而可能导致崩溃和安全问题。

+   第二个特征与第一个特征有类似的后果。通过使接口使用起来不太直观，您使用户更容易犯错误。

+   第三个特征是第二个特征的一个变体，但有一个额外的转折。用户不仅需要记住哪些参数是输入，哪些是输出，还需要记住如何处理输出。谁管理资源的创建和删除？这是如何实现的？背后的内存管理模型是什么？

使用现代 C++，返回包含所有必要数据的值比以往任何时候都更容易。通过对成对、元组和向量的使用，没有理由使用输出参数。此外，返回值有助于接受不修改对象状态的做法。这反过来又减少了与并发相关的问题。

+   最后一个特征引入了不必要的认知负荷，就像前面的例子一样，可能导致错误，最终导致失败。这样的代码也更难测试和维护，因为每次引入的更改都必须考虑到已经存在的所有可能的组合。未能正确处理任何组合都是对系统的潜在威胁。

接口的前述规则适用于接口的外部部分。您还应该通过验证输入、确保值正确和合理，并防止接口提供的服务被不必要地使用来对内部部分应用类似的措施。

### 启用自动资源管理

系统不稳定也可能是由于内存泄漏、数据竞争和死锁引起的。所有这些症状都是资源管理不善的表现。尽管资源管理是一个难题，但有一种机制可以帮助您减少问题的数量。这样的机制之一是自动资源管理。

在这种情况下，资源是通过操作系统获得访问权限的东西，您必须确保正确使用它。这可能意味着使用动态分配的内存、打开文件、套接字、进程或线程。当您获取它们和释放它们时，所有这些都需要采取特定的操作。其中一些在其生命周期内还需要特定的操作。在正确的时间释放这些资源失败会导致泄漏。由于资源通常是有限的，从长远来看，泄漏将导致无法创建新资源时出现意外行为。

资源管理在 C++中非常重要，因为与许多其他高级语言不同，C++中没有垃圾回收，软件开发人员负责资源的生命周期。了解这种生命周期有助于创建安全稳定的系统。

资源管理最常见的习惯用法是**资源获取即初始化**（**RAII**）。尽管它起源于 C++，但它也被用于其他语言，如 Vala 和 Rust。这种习惯用法使用对象的构造函数和析构函数来分配和释放资源。这样，我们可以保证在持有资源的对象超出范围时，资源将被正确释放。

在标准库中使用此习惯用法的一些示例是`std::unique_ptr`和`std::shared_ptr`智能指针类型。其他示例包括互斥锁-`std::lock_guard`、`std::unique_lock`和`std:shared_lock`-或文件-`std::ifstream`和`std::ofstream`。

**指南支持库**（**GSL**），我们将很快讨论，还实现了一项特别有用的自动资源管理指南。通过在我们的代码中使用`gsl::finally()`函数，我们创建了一个附有一些代码的`gsl::final_action()`对象。当对象的析构函数被调用时，这些代码将被执行。这意味着该代码将在成功从函数返回时执行，以及在发生异常期间进行堆栈展开时执行。

这种方法不应该经常使用，因为通常最好在设计类时考虑 RAII。但如果您正在与第三方模块进行接口，并且希望确保包装器的安全性，`finally()`可以帮助您实现这一点。

举个例子，假设我们有一个支付操作员，每个账户只允许一个并发登录。如果我们不想阻止用户进行未来的支付，我们应该在完成交易处理后立即注销。当一切按照我们的设计进行时，这并不是一个问题。但在发生异常时，我们也希望安全地释放资源。以下是我们可以使用`gsl::finally()`来实现的方式：

```cpp
TransactionStatus processTransaction(AccountName account, ServiceToken token,

Amount amount)

{

  payment::login(account, token);

  auto _ = gsl::finally([] { payment::logout(); });

  payment::process(amount); // We assume this can lead to exception


  return TransactionStatus::TransactionSuccessful;

}
```

无论在调用`payment::process()`期间发生了什么，我们至少可以保证在退出`processTransaction()`的范围时注销用户。

简而言之，使用 RAII 使您在类设计阶段更多地考虑资源管理，同时在您完全控制代码并且在您使用接口时不再那么清晰时，您不再那么考虑。

### 并发的缺点及如何处理

虽然并发可以提高性能和资源利用率，但也使您的代码更难设计和调试。这是因为，与单线程流程不同，操作的时间无法提前确定。在单线程代码中，您要么写入资源，要么从中读取，但您总是知道操作的顺序，因此可以预测对象的状态。

并发时，多个线程或进程可以同时从对象中读取或修改。如果修改不是原子的，我们可能会遇到常见更新问题的变体之一。考虑以下代码：

```cpp
TransactionStatus chargeTheAccount(AccountNumber acountNumber, Amount amount)

{

  Amount accountBalance = getAcountBalance(accountNumber);

  if (accountBalance > amount)

  {

    setAccountBalance(accountNumber, accountBalance - amount);

    return TransactionStatus::TransactionSuccessful;

  }

  return TransactionStatus::InsufficientFunds;

}
```

调用`chargeTheAccount`函数时，从非并发代码中，一切都会顺利进行。我们的程序将检查账户余额，并在可能的情况下进行扣款。然而，并发执行可能会导致负余额。这是因为两个线程可以依次调用`getAccountBalance()`，它将返回相同的金额，比如`20`。在执行完该调用后，两个线程都会检查当前余额是否高于可用金额。最后，在检查后，它们修改账户余额。假设两个交易金额都为`10`，每个线程都会将余额设置为 20-10=10。在*两个*操作之后，账户的余额为 10，尽管它应该是 0！

为了减轻类似问题，我们可以使用诸如互斥锁和临界区、CPU 提供的原子操作或并发安全数据结构等解决方案。

互斥锁、临界区和其他类似的并发设计模式可以防止多个线程修改（或读取）数据。尽管它们在设计并发应用程序时很有用，但与之相关的是一种权衡。它们有效地使您的代码的某些部分变成单线程。这是因为由互斥锁保护的代码只允许一个线程执行；其他所有线程都必须等待，直到互斥锁被释放。由于我们引入了等待，即使我们最初的目标是使代码更具性能，我们也可能使代码的性能下降。

原子操作意味着使用单个 CPU 指令来获得期望的效果。这个术语可以指任何将高级操作转换为单个 CPU 指令的操作。当单个指令实现的效果*超出*通常可能的范围时，它们特别有趣。例如，**比较和交换**（**CAS**）是一种指令，它将内存位置与给定值进行比较，并仅在比较成功时将该位置的内容修改为新值。自 C++11 以来，有一个`<std::atomic>`头文件可用，其中包含几种原子数据类型和操作。例如，CAS 被实现为一组`compare_and_exchange_*`函数。

最后，并发安全的数据结构（也称为并发数据结构）为数据结构提供了安全的抽象，否则这些数据结构将需要某种形式的同步。例如，Boost.Lockfree（[`www.boost.org/doc/libs/1_66_0/doc/html/lockfree.html`](https://www.boost.org/doc/libs/1_66_0/doc/html/lockfree.html)）库提供了用于多个生产者和多个消费者的并发队列和栈。libcds（[`github.com/khizmax/libcds`](https://github.com/khizmax/libcds)）还提供了有序列表、集合和映射，但截至撰写本书时，已经有几年没有更新了。

在设计并发处理时要牢记的有用规则如下：

+   首先考虑是否需要并发。

+   通过值传递数据，而不是通过指针或引用。这可以防止其他线程在读取数据时修改该值。

+   如果数据的大小使得按值共享变得不切实际，可以使用`shared_ptr`。这样，更容易避免资源泄漏。

## 安全编码、指南和 GSL

标准 C++基金会发布了一套指南，记录了构建 C++系统的最佳实践。这是一个在 GitHub 上发布的 Markdown 文档，网址为[`github.com/isocpp/CppCoreGuidelines`](https://github.com/isocpp/CppCoreGuidelines)。这是一个不断发展的文档，没有发布计划（不像 C++标准本身）。这些指南针对的是现代 C++，基本上意味着实现了至少 C++11 特性的代码库。

指南中提出的许多规则涵盖了我们在本章中介绍的主题。例如，有关接口设计、资源管理和并发的规则。指南的编辑是 Bjarne Stroustrup 和 Herb Sutter，他们都是 C++社区中受尊敬的成员。

我们不会详细描述这些指南。我们鼓励您自己阅读。本书受到其中许多规则的启发，并在我们的示例中遵循这些规则。

为了方便在各种代码库中使用这些规则，微软发布了**指南支持库**（**GSL**）作为一个开源项目，托管在[`github.com/microsoft/GSL`](https://github.com/microsoft/GSL)上。这是一个仅包含头文件的库，您可以将其包含在项目中以使用定义的类型。您可以包含整个 GSL，也可以选择性地仅使用您计划使用的一些类型。

该库的另一个有趣之处在于它使用 CMake 进行构建，Travis 进行持续集成，以及 Catch 进行单元测试。因此，它是我们在第七章、*构建和打包*，第八章、*可测试代码编写*和第九章、*持续集成和持续部署*中涵盖的主题的一个很好的例子。

## 防御性编码，验证一切

在前一章中，我们提到了防御性编程的方法。尽管这种方法并不严格属于安全功能，但它确实有助于创建健壮的接口。这样的接口反过来又增加了系统的整体安全性。

作为一个很好的启发式方法，您可以将所有外部数据视为不安全。我们所说的外部数据是通过某个接口（编程接口或用户界面）进入系统的每个输入。为了表示这一点，您可以在适当的类型前加上`Unsafe`前缀，如下所示：

```cpp
RegistrationResult registerUser(UnsafeUsername username, PasswordHash passwordHash)

{

  SafeUsername safeUsername = username.sanitize();

  try

  {

    std::unique_ptr<User> user = std::make_unique<User>(safeUsername, passwordHash);

    CommitResult result = user->commit();

    if (result == CommitResult::CommitSuccessful)

    {

      return RegistrationResult::RegistrationSuccessful;

    }

    else

    {

      return RegistrationResult::RegistrationUnsuccessful;

    }

  }

  catch (UserExistsException _)

  {

    return RegistrationResult::UserExists;

  }

}
```

如果您已经阅读了指南，您将知道通常应避免直接使用 C API。C API 中的一些函数可能以不安全的方式使用，并需要特别小心地防御性使用它们。最好使用 C++中相应的概念，以确保更好的类型安全性和保护（例如，防止缓冲区溢出）。

防御性编程的另一个方面是智能地重用现有代码。每次尝试实现某种技术时，请确保没有其他人在您之前实现过它。当您学习一种新的编程语言时，自己编写排序算法可能是一种有趣的挑战，但对于生产代码，最好使用标准库中提供的排序算法。对于密码哈希也是一样。毫无疑问，您可以找到一些聪明的方法来计算密码哈希并将其存储在数据库中，但通常更明智的做法是使用经过验证的`bcrypt`。请记住，智能的代码重用假设您以与您自己的代码一样的尽职调查检查和审计第三方解决方案。我们将在下一节“我的依赖项安全吗？”中深入探讨这个话题。

值得注意的是，防御性编程不应该变成偏执的编程。检查用户输入是明智的做法，而在初始化变量后立即断言初始化变量是否仍然等于原始值则有些过分。您希望控制数据和算法的完整性以及第三方解决方案的完整性。您不希望通过采用语言特性来验证编译器的正确性。

简而言之，从安全性和可读性的角度来看，使用 C++核心指南中提出的`Expects()`和`Ensures()`以及通过类型和转换区分不安全和安全数据是一个好主意。

## 最常见的漏洞

要检查您的代码是否安全防范最常见的漏洞，您应首先了解这些漏洞。毕竟，只有当您知道攻击是什么样子时，防御才有可能。**开放式网络应用安全项目**（**OWASP**）已经对最常见的漏洞进行了分类，并在[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)上发布了它们。在撰写本书时，这些漏洞如下：

+   注入：通常称为 SQL 注入。这不仅限于 SQL；当不受信任的数据直接传递给解释器（如 SQL 数据库、NoSQL 数据库、shell 或 eval 函数）时，就会出现这种漏洞。攻击者可能以这种方式访问应该受到保护的系统部分。

+   **破坏的身份验证**：如果身份验证实施不当，攻击者可能利用漏洞来获取秘密数据或冒充其他用户。

+   **敏感数据暴露**：缺乏加密和适当的访问权限可能导致敏感数据被公开。

+   **XML 外部实体**（**XXE**）：一些 XML 处理器可能会泄露服务器文件系统的内容或允许远程代码执行。

+   **破坏的访问控制**：当访问控制未正确执行时，攻击者可能会访问应受限制的文件或数据。

+   **安全配置错误**：使用不安全的默认值和不正确的配置是最常见的漏洞来源。

+   **跨站脚本攻击**（**XSS**）：包括并执行不受信任的外部数据，特别是使用 JavaScript，这允许控制用户的网络浏览器。

+   **不安全的反序列化**：一些有缺陷的解析器可能会成为拒绝服务攻击或远程代码执行的牺牲品。

+   **使用已知漏洞的组件**：现代应用程序中的许多代码都是第三方组件。这些组件应该定期进行审计和更新，因为单个依赖中已知的安全漏洞可能导致整个应用程序和数据被攻击。幸运的是，有一些工具可以帮助自动化这一过程。

+   **日志和监控不足**：如果你的系统受到攻击，而你的日志和监控不够彻底，攻击者可能会获得更深入的访问权限，而你却没有察觉。

我们不会详细介绍每个提到的漏洞。我们想要强调的是，通过将所有外部数据视为不安全，你可以首先通过删除所有不安全的内容来对其进行净化，然后再开始实际处理。

当涉及到日志和监控不足时，我们将在第十五章中详细介绍*云原生设计*。在那里，我们将介绍一些可能的可观察性方法，包括日志记录、监控和分布式跟踪。

# 检查依赖是否安全

计算机早期，所有程序都是单体结构，没有任何外部依赖。自操作系统诞生以来，任何非平凡的软件很少能摆脱依赖。这些依赖可以分为两种形式：外部依赖和内部依赖。

+   外部依赖是我们运行应用程序时应该存在的环境。例如，前面提到的操作系统、动态链接库和其他应用程序（如数据库）。

+   内部依赖是我们想要重用的模块，因此通常是静态库或仅包含头文件的库。

两种依赖都提供潜在的安全风险。随着每一行代码增加漏洞的风险，你拥有的组件越多，你的系统可能受到攻击的机会就越高。在接下来的章节中，我们将看到如何检查你的软件是否确实容易受到已知的漏洞攻击。

## 通用漏洞和暴露

检查软件中已知的安全问题的第一个地方是**通用漏洞和暴露**（**CVE**）列表，可在[`cve.mitre.org/`](https://cve.mitre.org/)上找到。该列表由几个被称为**CVE 编号机构**（**CNAs**）的机构不断更新。这些机构包括供应商和项目、漏洞研究人员、国家和行业 CERT 以及漏洞赏金计划。

该网站还提供了一个搜索引擎。通过这个，你可以使用几种方法了解漏洞：

+   你可以输入漏洞编号。这些编号以`CVE`为前缀，例如 CVE-2014-6271，臭名昭著的 ShellShock，或者 CVE-2017-5715，也被称为 Spectre。

+   你可以输入漏洞的通用名称，比如前面提到的 ShellShock 或 Spectre。

+   你可以输入你想审计的软件名称，比如 Bash 或 Boost。

对于每个搜索结果，你可以看到描述以及其他 bug 跟踪器和相关资源的参考列表。描述通常列出受漏洞影响的版本，因此你可以检查你计划使用的依赖是否已经修补。

## 自动化扫描器

有一些工具可以帮助您审计依赖项列表。其中一个工具是 OWASP Dependency-Check ([`www.owasp.org/index.php/OWASP_Dependency_Check`](https://www.owasp.org/index.php/OWASP_Dependency_Check))。尽管它只正式支持 Java 和.NET，但它对 Python、Ruby、Node.js 和 C++（与 CMake 或`autoconf`一起使用时）有实验性支持。除了作为独立工具使用外，它还可以与 Jenkins、SonarQube 和 CircleCI 等**持续集成/持续部署**（**CI/CD**）软件集成。

另一个允许检查已知漏洞的依赖项的工具是 Snyk。这是一个商业产品，有几个支持级别。与 OWASP Dependency-Check 相比，它还可以执行更多操作，因为 Snyk 还可以审计容器映像和许可合规性问题。它还提供了更多与第三方解决方案的集成。

## 自动化依赖项升级管理

监视依赖项的漏洞只是确保项目安全的第一步。之后，您需要采取行动并手动更新受损的依赖项。正如您可能已经预料到的那样，也有专门的自动化解决方案。其中之一是 Dependabot，它会扫描您的源代码存储库，并在有安全相关更新可用时发布拉取请求。在撰写本书时，Dependabot 尚不支持 C++。但是，它可以与您的应用程序可能使用的其他语言一起使用。除此之外，它还可以扫描 Docker 容器，查找基础映像中发现的漏洞。

自动化依赖项管理需要成熟的测试支持。在没有测试的情况下切换依赖项版本可能会导致不稳定和错误。防止与依赖项升级相关的问题的一种保护措施是使用包装器与第三方代码进行接口。这样的包装器可能有自己的一套测试，可以在升级期间立即告诉我们接口何时被破坏。

# 加固您的代码

通过使用现代 C++构造而不是较旧的 C 等效构造，可以减少自己代码中常见的安全漏洞数量。然而，即使更安全的抽象也可能存在漏洞。仅仅选择更安全的实现并认为自己已经尽了最大努力是不够的。大多数情况下，都有方法可以进一步加固您的代码。

但是什么是代码加固？根据定义，这是减少系统漏洞表面的过程。通常，这意味着关闭您不会使用的功能，并追求一个简单的系统而不是一个复杂的系统。这也可能意味着使用工具来增加已有功能的健壮性。

这些工具可能意味着在操作系统级别应用内核补丁、防火墙和**入侵检测系统**（**IDSes**）。在应用程序级别，这可能意味着使用各种缓冲区溢出和下溢保护机制，使用容器和**虚拟机**（**VMs**）进行特权分离和进程隔离，或者强制执行加密通信和存储。

在本节中，我们将重点介绍应用程序级别的一些示例，而下一节将重点介绍操作系统级别。

## 面向安全的内存分配器

如果您认真保护应用程序免受与堆相关的攻击，例如堆溢出、释放后使用或双重释放，您可能会考虑用面向安全的版本替换标准内存分配器。可能感兴趣的两个项目如下：

+   FreeGuard，可在[`github.com/UTSASRG/FreeGuard`](https://github.com/UTSASRG/FreeGuard)上找到，并在[`arxiv.org/abs/1709.02746`](https://arxiv.org/abs/1709.02746)的论文中描述

+   GrapheneOS 项目的`hardened_malloc`，可在[`github.com/GrapheneOS/hardened_malloc`](https://github.com/GrapheneOS/hardened_malloc)上找到

FreeGuard 于 2017 年发布，自那时以来除了零星的错误修复外，没有太多变化。另一方面，`hardened_malloc`正在积极开发。这两个分配器都旨在作为标准`malloc()`的替代品。您可以通过设置`LD_PRELOAD`环境变量或将库添加到`/etc/preload.so`配置文件中，而无需修改应用程序即可使用它们。虽然 FreeGuard 针对的是 64 位 x86 系统上的 Linux 与 Clang 编译器，`hardened_malloc`旨在更广泛的兼容性，尽管目前主要支持 Android 的 Bionic，`musl`和`glibc`。`hardened_malloc`也基于 OpenBSD 的`alloc`，而 OpenBSD 本身是一个以安全为重点的项目。

不要替换内存分配器，可以替换你用于更安全的集合。 SaferCPlusPlus（[`duneroadrunner.github.io/SaferCPlusPlus/`](https://duneroadrunner.github.io/SaferCPlusPlus/)）项目提供了`std::vector<>`，`std::array<>`和`std::string`的替代品，可以作为现有代码中的替代品。该项目还包括用于保护未初始化使用或符号不匹配的基本类型的替代品，并发数据类型的替代品，以及指针和引用的替代品。

## 自动化检查

有一些工具可以特别有助于确保正在构建的系统的安全。我们将在下一节中介绍它们。

### 编译器警告

虽然编译器警告本身不一定是一个工具，但可以使用和调整编译器警告，以实现更好的输出，从而使每个 C++开发人员都将使用的 C++编译器获得更好的输出。

由于编译器已经可以进行一些比标准要求更深入的检查，建议利用这种可能性。当使用诸如 GCC 或 Clang 之类的编译器时，推荐的设置包括`-Wall -Wextra`标志。这将生成更多的诊断，并在代码不遵循诊断时产生警告。如果您想要非常严格，还可以启用`-Werror`，这将把所有警告转换为错误，并阻止不能通过增强诊断的代码的编译。如果您想严格遵循标准，还有`-pedantic`和`-pedantic-errors`标志，将检查是否符合标准。

在使用 CMake 进行构建时，您可以使用以下函数在编译期间启用这些标志：

```cpp
add_library(customer ${SOURCES_GO_HERE})

target_include_directories(customer PUBLIC include)

target_compile_options(customer PRIVATE -Werror -Wall -Wextra)
```

这样，除非您修复编译器报告的所有警告（转换为错误），否则编译将失败。

您还可以在 OWASP（[`www.owasp.org/index.php/C-Based_Toolchain_Hardening`](https://www.owasp.org/index.php/C-Based_Toolchain_Hardening)）和 Red Hat（[`developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/`](https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/)）的文章中找到工具链加固的建议设置。

### 静态分析

一类可以帮助使您的代码更安全的工具是所谓的**静态应用安全测试**（**SAST**）工具。它们是专注于安全方面的静态分析工具的变体。

SAST 工具很好地集成到 CI/CD 管道中，因为它们只是读取您的源代码。输出通常也适用于 CI/CD，因为它突出显示了源代码中特定位置发现的问题。另一方面，静态分析可能会忽略许多类型的问题，这些问题无法自动发现，或者仅通过静态分析无法发现。这些工具也对与配置相关的问题视而不见，因为配置文件并未在源代码本身中表示。

C++ SAST 工具的示例包括以下开源解决方案：

+   Cppcheck（[`cppcheck.sourceforge.net/`](http://cppcheck.sourceforge.net/)）是一个通用的静态分析工具，专注于较少的误报。

+   Flawfinder（[`dwheeler.com/flawfinder/`](https://dwheeler.com/flawfinder/)），似乎没有得到积极维护

+   LGTM（[`lgtm.com/help/lgtm/about-lgtm`](https://lgtm.com/help/lgtm/about-lgtm)），支持多种不同的语言，并具有对拉取请求的自动化分析功能

+   SonarQube（[`www.sonarqube.org/`](https://www.sonarqube.org/)）具有出色的 CI/CD 集成和语言覆盖，并提供商业版本

还有商业解决方案可用：

+   Checkmarx CxSAST（[`www.checkmarx.com/products/static-application-security-testing/`](https://www.checkmarx.com/products/static-application-security-testing/)），承诺零配置和广泛的语言覆盖

+   CodeSonar（[`www.grammatech.com/products/codesonar`](https://www.grammatech.com/products/codesonar)），专注于深度分析和发现最多的缺陷

+   Klocwork（[`www.perforce.com/products/klocwork`](https://www.perforce.com/products/klocwork)），专注于准确性

+   Micro Focus Fortify（[`www.microfocus.com/en-us/products/static-code-analysis-sast/overview`](https://www.microfocus.com/en-us/products/static-code-analysis-sast/overview)），支持广泛的语言并集成了同一制造商的其他工具

+   Parasoft C/C++test（[`www.parasoft.com/products/ctest`](https://www.parasoft.com/products/ctest)），这是一个集成的静态和动态分析、单元测试、跟踪等解决方案

+   MathWorks 的 Polyspace Bug Finder（[`www.mathworks.com/products/polyspace-bug-finder.html`](https://www.mathworks.com/products/polyspace-bug-finder.html)），集成了 Simulink 模型

+   Veracode 静态分析（[`www.veracode.com/products/binary-static-analysis-sast`](https://www.veracode.com/products/binary-static-analysis-sast)），这是一个用于静态分析的 SaaS 解决方案

+   WhiteHat Sentinel Source（[`www.whitehatsec.com/platform/static-application-security-testing/`](https://www.whitehatsec.com/platform/static-application-security-testing/)），也专注于消除误报

### 动态分析

就像静态分析是在源代码上执行的一样，动态分析是在生成的二进制文件上执行的。名称中的“动态”指的是观察代码在处理实际数据时的行为。当专注于安全性时，这类工具也可以被称为**动态应用安全性测试**（**DAST**）。

它们相对于 SAST 工具的主要优势在于，它们可以发现许多从源代码分析角度看不到的流程。当然，这也带来了一个缺点，即您必须运行应用程序才能进行分析。而且我们知道，运行应用程序可能既耗时又耗内存。

DAST 工具通常专注于与 Web 相关的漏洞，如 XSS、SQL（和其他）注入或泄露敏感信息。我们将在下一小节中更多地关注一个更通用的动态分析工具 Valgrind。

#### Valgrind 和 Application Verifier

Valgrind 主要以内存泄漏调试工具而闻名。实际上，它是一个帮助构建与内存问题无关的动态分析工具的仪器框架。除了内存错误检测器外，该套工具目前还包括线程错误检测器、缓存和分支预测分析器以及堆分析器。它在类 Unix 操作系统（包括 Android）上支持各种平台。

基本上，Valgrind 充当虚拟机，首先将二进制文件转换为称为中间表示的简化形式。它不是在实际处理器上运行程序，而是在这个虚拟机下执行，以便分析和验证每个调用。

如果您在 Windows 上开发，可以使用**Application Verifier**（**AppVerifier**）代替 Valgrind。AppVerifier 可以帮助您检测稳定性和安全性问题。它可以监视运行中的应用程序和用户模式驱动程序，以查找内存问题，如泄漏和堆破坏，线程和锁定问题，句柄的无效使用等。

#### 消毒剂

消毒剂是基于代码的编译时仪器的动态测试工具。它们可以帮助提高系统的整体稳定性和安全性，避免未定义的行为。在[`github.com/google/sanitizers`](https://github.com/google/sanitizers)，您可以找到 LLVM（Clang 基于此）和 GCC 的实现。它们解决了内存访问、内存泄漏、数据竞争和死锁、未初始化内存使用以及未定义行为的问题。

**AddressSanitizer**（**ASan**）可保护您的代码免受与内存寻址相关的问题，如全局缓冲区溢出，释放后使用或返回后使用堆栈。尽管它是同类解决方案中最快的之一，但仍会使进程减速约两倍。最好在运行测试和进行开发时使用它，但在生产构建中关闭它。您可以通过向 Clang 添加`-fsanitize=address`标志来为您的构建启用它。

**AddressSanitizerLeakSanitizer**（**LSan**）与 ASan 集成以查找内存泄漏。它在 x86_64 Linux 和 x86_64 macOS 上默认启用。它需要设置一个环境变量，`ASAN_OPTIONS=detect_leaks=1`。LSan 在进程结束时执行泄漏检测。LSan 也可以作为一个独立库使用，而不需要 AddressSanitizer，但这种模式测试较少。

**ThreadSanitizer**（**TSan**），正如我们之前提到的，可以检测并发问题，如数据竞争和死锁。您可以使用`-fsanitize=thread`标志启用它到 Clang。

**MemorySanitizer**（**MSan**）专注于与对未初始化内存的访问相关的错误。它实现了我们在前一小节中介绍的 Valgrind 的一些功能。MSan 支持 64 位 x86、ARM、PowerPC 和 MIPS 平台。您可以通过向 Clang 添加`-fsanitize=memory -fPIE -pie`标志来启用它（这也会打开位置无关可执行文件，这是我们稍后将讨论的概念）。

**硬件辅助地址消毒剂**（**HWASAN**）类似于常规 ASan。主要区别在于尽可能使用硬件辅助。目前，此功能仅适用于 64 位 ARM 架构。

**UndefinedBehaviorSanitizer**（**UBSan**）寻找未定义行为的其他可能原因，如整数溢出、除以零或不正确的位移操作。您可以通过向 Clang 添加`-fsanitize=undefined`标志来启用它。

尽管消毒剂可以帮助您发现许多潜在问题，但它们只有在您对其进行测试时才有效。在使用消毒剂时，请记住保持测试的代码覆盖率高，否则您可能会产生一种虚假的安全感。

#### 模糊测试

作为 DAST 工具的一个子类，模糊测试检查应用程序在面对无效、意外、随机或恶意形成的数据时的行为。在针对跨越信任边界的接口（如最终用户文件上传表单或输入）时，此类检查尤其有用。

此类别中的一些有趣工具包括以下内容：

+   Peach Fuzzer：[`www.peach.tech/products/peach-fuzzer/`](https://www.peach.tech/products/peach-fuzzer/)

+   PortSwigger Burp：[`portswigger.net/burp`](https://portswigger.net/burp)

+   OWASP Zed Attack Proxy 项目：[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)

+   Google 的 ClusterFuzz：[`github.com/google/clusterfuzz`](https://github.com/google/clusterfuzz)（和 OSS-Fuzz：[`github.com/google/oss-fuzz`](https://github.com/google/oss-fuzz)）

## 进程隔离和沙箱

如果您想在自己的环境中运行未经验证的软件，您可能希望将其与系统的其余部分隔离开来。通过虚拟机、容器或 AWS Lambda 使用的 Firecracker（[`firecracker-microvm.github.io/`](https://firecracker-microvm.github.io/)）等微型虚拟机，可以对执行的代码进行沙盒化。

这样，一个应用程序的崩溃、泄漏和安全问题不会传播到整个系统，使其变得无用或者受到威胁。由于每个进程都有自己的沙盒，最坏的情况就是只丢失这一个服务。

对于 C 和 C++代码，还有一个由谷歌领导的开源项目**Sandboxed API**（**SAPI**；[`githu`](https://github.com/google/sandboxed-api)[b.com/google/sandboxed-api](https://github.com/google/sandboxed-api)[)，它允许构建沙盒不是为整个进程，而是为库。它被谷歌自己的 Chrome 和 Chromium 网页浏览器等使用。](https://github.com/google/sandboxed-api)

即使虚拟机和容器可以成为进程隔离策略的一部分，也不要将它们与微服务混淆，后者通常使用类似的构建模块。微服务是一种架构设计模式，它们并不自动等同于更好的安全性。

# 加固您的环境

即使您采取了必要的预防措施，确保您的依赖项和代码没有已知的漏洞，仍然存在一个可能会危及您的安全策略的领域。所有应用程序都需要一个执行环境，这可能意味着容器、虚拟机或操作系统。有时，这也可能意味着底层基础设施。

当运行应用程序的操作系统具有开放访问权限时，仅仅使应用程序达到最大程度的硬化是不够的。这样，攻击者可以从系统或基础设施级别直接获取未经授权的数据，而不是针对您的应用程序。

本节将重点介绍一些硬化技术，您可以在执行的最低级别应用这些技术。

## 静态与动态链接

链接是在编译后发生的过程，当您编写的代码与其各种依赖项（如标准库）结合在一起时。链接可以在构建时、加载时（操作系统执行二进制文件时）或运行时发生，如插件和其他动态依赖项的情况。最后两种用例只可能发生在动态链接中。

那么，动态链接和静态链接有什么区别呢？使用静态链接，所有依赖项的内容都会被复制到生成的二进制文件中。当程序加载时，操作系统将这个单一的二进制文件放入内存并执行它。静态链接是由称为链接器的程序在构建过程的最后一步执行的。

由于每个可执行文件都必须包含所有的依赖项，静态链接的程序往往体积较大。这也有其好处；因为执行所需的一切都已经在一个地方可用，所以执行速度可能会更快，并且加载程序到内存中所需的时间总是相同的。对依赖项的任何更改都需要重新编译和重新链接；没有办法升级一个依赖项而不改变生成的二进制文件。

在动态链接中，生成的二进制文件包含您编写的代码，但是依赖项的内容被替换为需要单独加载的实际库的引用。在加载时，动态加载器的任务是找到适当的库并将它们加载到内存中与您的二进制文件一起。当多个应用程序同时运行并且它们每个都使用类似的依赖项（例如 JSON 解析库或 JPEG 处理库）时，动态链接的二进制文件将导致较低的内存使用率。这是因为只有一个给定库的副本可以加载到内存中。相比之下，使用静态链接的二进制文件中相同的库会作为结果的一部分一遍又一遍地加载。当您需要升级其中一个依赖项时，您可以在不触及系统的任何其他组件的情况下进行。下次加载应用程序到内存时，它将自动引用新升级的组件。

静态和动态链接也具有安全性影响。更容易未经授权地访问动态链接的应用程序。这可以通过在常规库的位置替换受损的动态库或在每次新执行的进程中预加载某些库来实现。

当您将静态链接与容器结合使用时（在后面的章节中详细解释），您将获得小型、安全、沙箱化的执行环境。您甚至可以进一步使用这些容器与基于微内核的虚拟机，从而大大减少攻击面。

## 地址空间布局随机化

**地址空间布局随机化**（**ASLR**）是一种用于防止基于内存的攻击的技术。它通过用随机化的内存布局替换程序和数据的标准布局来工作。这意味着攻击者无法可靠地跳转到在没有 ASLR 的系统上本来存在的特定函数。

当与**不执行**（**NX**）位支持结合使用时，这种技术可以变得更加有效。NX 位标记内存中的某些页面，例如堆和栈，只包含不能执行的数据。大多数主流操作系统都已实现了 NX 位支持，并且可以在硬件支持时使用。

## DevSecOps

为了按可预测的方式交付软件增量，最好采用 DevOps 理念。简而言之，DevOps 意味着打破传统模式，鼓励业务、软件开发、软件运营、质量保证和客户之间的沟通。DevSecOps 是 DevOps 的一种形式，它还强调了在每个步骤中考虑安全性的必要性。

这意味着您正在构建的应用程序从一开始就具有内置的可观察性，利用 CI/CD 流水线，并定期扫描漏洞。DevSecOps 使开发人员在基础架构设计中发挥作用，并使运营专家在构成应用程序的软件包设计中发挥作用。由于每个增量代表一个可工作的系统（尽管不是完全功能的），因此安全审计定期进行，所需时间比正常情况下少。这导致更快速和更安全的发布，并允许更快地对安全事件做出反应。

# 总结

在本章中，我们讨论了安全系统的不同方面。由于安全性是一个复杂的主题，您不能仅从自己的应用程序的角度来处理它。现在所有的应用程序都在某种环境中运行，要么控制这个环境并根据您的要求塑造它，要么通过沙箱化和隔离代码来保护自己免受环境的影响。

阅读完本章后，您现在可以开始搜索依赖项和自己代码中的漏洞。您知道如何设计增强安全性的系统以及使用哪些工具来发现可能的缺陷。保持安全是一个持续的过程，但良好的设计可以减少未来的工作量。

下一章将讨论可扩展性以及在系统扩展时可能面临的各种挑战。

# 问题

1.  为什么安全在现代系统中很重要？

1.  并发的一些挑战是什么？

1.  C++核心指南是什么？

1.  安全编码和防御性编码有什么区别？

1.  您如何检查您的软件是否包含已知的漏洞？

1.  静态分析和动态分析有什么区别？

1.  静态链接和动态链接有什么区别？

1.  您如何使用编译器来解决安全问题？

1.  您如何在 CI 流程中实施安全意识？

# 进一步阅读

**一般的网络安全**：

+   [`www.packtpub.com/eu/networking-and-servers/hands-cybersecurity-architects`](https://www.packtpub.com/eu/networking-and-servers/hands-cybersecurity-architects)

+   [`www.packtpub.com/eu/networking-and-servers/information-security-handbook`](https://www.packtpub.com/eu/networking-and-servers/information-security-handbook)

+   [`www.owasp.org/index.php/Main_Page`](https://www.owasp.org/index.php/Main_Page)

+   [`www.packtpub.com/eu/networking-and-servers/practical-security-automation-and-testing`](https://www.packtpub.com/eu/networking-and-servers/practical-security-automation-and-testing)

**并发**：

+   [`www.packtpub.com/eu/application-development/concurrent-patterns-and-best-practices`](https://www.packtpub.com/eu/application-development/concurrent-patterns-and-best-practices)

+   [`www.packtpub.com/eu/application-development/mastering-c-multithreading`](https://www.packtpub.com/eu/application-development/mastering-c-multithreading)

**操作系统加固**：

+   [`www.packtpub.com/eu/networking-and-servers/mastering-linux-security-and-hardening`](https://www.packtpub.com/eu/networking-and-servers/mastering-linux-security-and-hardening)


# 第十一章：性能

选择 C++作为项目的关键编程语言的最常见原因之一是出于性能要求。在性能方面，C++比竞争对手明显更有优势，但要取得最佳结果需要理解相关问题。本章重点介绍如何提高 C++软件的性能。我们将首先向您展示用于测量性能的工具。我们将向您展示一些增加单线程计算速度的技术。然后我们将讨论如何利用并行计算。最后，我们将展示如何使用 C++20 的协程进行非抢占式多任务处理。

本章将涵盖以下主题：

+   性能测量

+   帮助编译器生成高性能代码

+   并行计算

+   使用协程

首先，让我们指定在本章中运行示例所需的内容。

# 技术要求

要复制本章中的示例，您应安装以下内容：

+   CMake 3.15+

+   支持 C++20 的范围和协程的编译器，例如 GCC 10+

本章的源代码片段可以在[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter11`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter11)找到。

# 性能测量

要有效地提高代码的性能，您必须首先测量其性能。如果不知道实际瓶颈在哪里，最终会优化错误的地方，浪费时间，并且会对您的辛勤工作几乎没有收获感到惊讶和沮丧。在本节中，我们将展示如何使用基准测试正确测量性能，如何成功地对代码进行分析，并如何深入了解分布式系统的性能。

## 进行准确和有意义的测量

为了获得准确和可重复的测量结果，您可能还希望将计算机置于性能模式，而不是通常的默认节能模式。如果您需要系统低延迟，您可能希望永久禁用两台机器上的节能模式，并在生产环境中禁用节能模式。许多时候，这可能意味着进入 BIOS 并正确配置服务器。请注意，如果您使用公共云提供商，则可能无法做到这一点。如果您在计算机上拥有 root/admin 权限，操作系统通常也可以调整一些设置。例如，您可以通过在 Linux 系统上运行以下命令来强制 CPU 以最大频率运行：

```cpp
sudo cpupower frequency-set --governor performance
```

此外，为了获得有意义的结果，您可能希望在尽可能接近生产环境的系统上进行测量。除了配置之外，诸如 RAM 的不同速度、CPU 缓存的数量和 CPU 的微体系结构等方面也可能扭曲您的结果，并导致您得出错误的结论。硬盘设置、甚至网络拓扑和使用的硬件也是如此。您构建的软件也起着至关重要的作用：从固件使用，通过操作系统和内核，一直到软件堆栈和依赖项。最好有一个与您的生产环境相同的第二个环境，并使用相同的工具和脚本进行管理。

既然我们已经有了一个稳固的测量环境，让我们看看我们实际上可以测量些什么。

## 利用不同类型的测量工具

有几种测量性能的方法，每种方法都侧重于不同的范围。让我们逐一看看它们。

基准测试可用于测试系统在预先制定的测试中的速度。通常，它们会导致完成时间或每秒处理的订单等性能指标。有几种类型的基准测试：

+   **微基准测试**，您可以用它来测量小代码片段的执行。我们将在下一节中介绍它们。

+   **模拟**，这是对较大规模的人工数据进行的合成测试。如果您无法访问目标数据或目标硬件，它们可能会很有用。例如，当您计划检查您正在开发的硬件的性能，但它尚不存在，或者当您计划处理传入的流量，但只能假设流量的情况时。

+   **重放**，这是一种非常准确的衡量真实工作负载下性能的方法。其思想是记录进入生产系统的所有请求或工作负载，通常带有时间戳。然后可以将这些转储“重放”到基准系统中，尊重它们之间的时间差异，以检查其性能。这样的基准测试可以很好地看到代码或环境的潜在变化如何影响系统的延迟和吞吐量。

+   **行业标准**，这是一个很好的方法，可以看到我们的产品与竞争对手相比的表现。此类基准测试的示例包括用于 CPU 的 SuperPi，用于图形卡的 3D Mark 以及用于人工智能处理器的 ResNet-50。

除了基准测试之外，另一种在衡量性能时非常宝贵的工具是性能分析器。性能分析器不仅可以为您提供整体性能指标，还可以让您检查代码的执行情况并寻找瓶颈。它们对于捕捉减慢系统速度的意外情况非常有用。我们将在本章后面更详细地介绍它们。

掌握系统性能的最后一种方法是追踪。追踪本质上是在执行过程中记录系统行为的一种方式。通过监视请求完成各个处理步骤所需的时间（例如由不同类型的微服务处理），您可以洞察系统哪些部分需要改进性能，或者您的系统如何处理不同类型的请求：无论是不同类型的请求还是被接受或拒绝的请求。我们将在本章后面介绍追踪 - 就在性能分析之后。

现在让我们再多说几句关于微基准。

## 使用微基准测试

微基准测试用于衡量“微”代码片段的执行速度。如果您想知道如何实现特定功能，或者不同的第三方库如何处理相同的任务的速度，那么它们是完成此任务的完美工具。虽然它们不能代表真实环境，但它们非常适合执行这样的小型实验。

让我们展示如何使用 C++中最常用的框架之一来运行这样的实验：Google Benchmark。

### 设置 Google Benchmark

让我们首先通过 Conan 将库引入我们的代码中。将以下内容放入您的`conanfile.txt`中：

```cpp
[requires]

benchmark/1.5.2


[generators]

CMakeDeps
```

我们将使用 CMakeDeps 生成器，因为它是 Conan 2.0 中推荐的 CMake 生成器。它依赖于 CMake 的`find_package`功能来使用我们的原始依赖管理器安装的软件包。要安装它们的发布版本的依赖项，请运行以下命令：

```cpp
cd <build_directory>

conan install <source_directory> --build=missing -s build_type=Release
```

如果您正在使用自定义的 Conan 配置文件，请记得在这里也添加它。

从您的`CMakeLists.txt`文件中使用它也非常简单，如下所示：

```cpp
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}")

find_package(benchmark REQUIRED)
```

首先，我们将我们的构建目录添加到`CMAKE_PREFIX_PATH`中，以便 CMake 可以找到 Conan 生成的配置文件和/或目标文件。接下来，我们只需使用它们来找到我们的依赖项。

由于我们将创建多个微基准测试，我们可以使用一个 CMake 函数来帮助我们定义它们：

```cpp
function(add_benchmark NAME SOURCE)

  add_executable(${NAME} ${SOURCE})

  target_compile_features(${NAME} PRIVATE cxx_std_20)

  target_link_libraries(${NAME} PRIVATE benchmark::benchmark)

endfunction()
```

该函数将能够创建单一翻译单元的微基准测试，每个测试都使用 C++20 并链接到 Google Benchmark 库。现在让我们使用它来创建我们的第一个微基准测试可执行文件：

```cpp
add_benchmark(microbenchmark_1 microbenchmarking/main_1.cpp)
```

现在我们准备在源文件中放入一些代码。

### 编写您的第一个微基准测试

我们将尝试基准测试使用二分法在排序向量中进行查找时需要多快，与仅线性查找相比。让我们从创建排序向量的代码开始：

```cpp
using namespace std::ranges;


template <typename T>

auto make_sorted_vector(std::size_t size) {

  auto sorted = std::vector<T>{};

  sorted.reserve(size);


  auto sorted_view = views::iota(T{0}) | views::take(size);

  std::ranges::copy(sorted_view, std::back_inserter(sorted));

  return sorted;

}
```

我们的向量将包含大小元素，所有数字从 0 到大小-1 按升序排列。现在让我们指定我们要查找的元素和容器的大小：

```cpp
constexpr auto MAX_HAYSTACK_SIZE = std::size_t{10'000'000};

constexpr auto NEEDLE = 2137;
```

如您所见，我们将基准测试在干草垛中查找针需要多长时间。简单的线性搜索可以实现如下：

```cpp
void linear_search_in_sorted_vector(benchmark::State &state) {

  auto haystack = make_sorted_vector<int>(MAX_HAYSTACK_SIZE);

  for (auto _ : state) {

    benchmark::DoNotOptimize(find(haystack, NEEDLE));

  }

}
```

在这里，我们可以看到 Google Benchmark 的第一次使用。每个微基准测试应该接受`State`作为参数。这种特殊类型执行以下操作：

+   包含执行的迭代和测量计算所花费的时间的信息

+   计算所处理的字节数

+   如果需要，可以返回其他状态信息，例如需要进一步运行（通过`KeepRunning()`成员函数）

+   可以用于暂停和恢复迭代的计时（分别通过`PauseTiming()`和`ResumeTiming()`成员函数）

我们的循环中的代码将被测量，根据允许运行此特定基准测试的总时间进行所需的迭代。我们的干草垛的创建在循环外部，不会被测量。

在循环内部，有一个名为`DoNotOptimize`的辅助函数。它的目的是确保编译器不会摆脱我们的计算，因为它可以证明它们在这个范围之外是无关紧要的。在我们的情况下，它将标记`std::find`的结果是必要的，所以实际用于查找目标的代码不会被优化掉。使用诸如 objdump 或诸如 Godbolt 和 QuickBench 的网站等工具，可以查看您想要运行的代码是否已被优化掉。QuickBench 的额外优势在于在云中运行您的基准测试并在线共享其结果。

回到我们手头的任务，我们有一个线性搜索的微基准测试，所以现在让我们在另一个微基准测试中计时二进制搜索：

```cpp
void binary_search_in_sorted_vector(benchmark::State &state) {

  auto haystack = make_sorted_vector<int>(MAX_HAYSTACK_SIZE);

  for (auto _ : state) {

    benchmark::DoNotOptimize(lower_bound(haystack, NEEDLE));

  }

}
```

我们的新基准测试非常相似。它只在使用的函数上有所不同：`lower_bound`将执行二进制搜索。请注意，与我们的基本示例类似，我们甚至不检查迭代器返回的指向向量中的有效元素，还是指向其末尾。在`lower_bound`的情况下，我们可以检查迭代器下的元素是否实际上是我们要查找的元素。

现在我们有了微基准测试函数，让我们通过添加以下内容将它们创建为实际的基准测试：

```cpp
BENCHMARK(binary_search_in_sorted_vector);

BENCHMARK(linear_search_in_sorted_vector);
```

如果默认的基准测试设置对您来说没问题，那么您只需要通过。作为最后一步，让我们添加一个`main()`函数：

```cpp
BENCHMARK_MAIN();
```

就是这么简单！或者，您也可以链接我们的程序而不是`benchmark_main`。使用 Google Benchmark 的`main()`函数的优点是提供了一些默认选项。如果编译我们的基准测试并在传递`--help`作为参数运行它，您将看到以下内容：

```cpp
benchmark [--benchmark_list_tests={true|false}]

          [--benchmark_filter=<regex>]

          [--benchmark_min_time=<min_time>]

          [--benchmark_repetitions=<num_repetitions>]

          [--benchmark_report_aggregates_only={true|false}]

          [--benchmark_display_aggregates_only={true|false}]

          [--benchmark_format=<console|json|csv>]

          [--benchmark_out=<filename>]

          [--benchmark_out_format=<json|console|csv>]

          [--benchmark_color={auto|true|false}]

          [--benchmark_counters_tabular={true|false}]

          [--v=<verbosity>]
```

这是一组很好的功能。例如，在设计实验时，您可以使用`benchmark_format`开关获取 CSV 输出，以便更容易绘制图表。

现在让我们通过在编译后的可执行文件上不带命令行参数来看看我们的基准测试的运行情况。运行`./microbenchmark_1`的可能输出如下：

```cpp
2021-02-28T16:19:28+01:00

Running ./microbenchmark_1

Run on (8 X 2601 MHz CPU s)

Load Average: 0.52, 0.58, 0.59

-------------------------------------------------------------------------

Benchmark                               Time             CPU   Iterations

-------------------------------------------------------------------------

linear_search_in_sorted_vector        984 ns          984 ns       746667

binary_search_in_sorted_vector       18.9 ns         18.6 ns     34461538
```

从运行环境的一些数据开始（基准测试的时间、可执行文件名称、服务器的 CPU 和当前负载），我们得到了我们定义的每个基准测试的结果。对于每个基准测试，我们得到每次迭代的平均墙时间、每次迭代的平均 CPU 时间以及基准测试运行的迭代次数。默认情况下，单次迭代时间越长，迭代次数就越少。运行更多的迭代可以确保您获得更稳定的结果。

### 将任意参数传递给微基准测试

如果我们要测试处理手头问题的更多方法，我们可以寻找一种重用基准代码并将其传递给执行查找的函数的方法。Google Benchmark 具有一个我们可以使用的功能。该框架实际上允许我们通过将它们作为函数签名的附加参数来传递任何参数给基准。

让我们看看使用此功能的我们的基准的统一签名会是什么样子：

```cpp
void search_in_sorted_vector(benchmark::State &state, auto finder) {

  auto haystack = make_sorted_vector<int>(MAX_HAYSTACK_SIZE);

  for (auto _ : state) {

    benchmark::DoNotOptimize(finder(haystack, NEEDLE));

  }

}
```

您可以注意到函数的新`finder`参数，它用于我们之前调用`find`或`lower_bound`的位置。现在我们可以使用与上次不同的宏来创建我们的两个微基准测试：

```cpp
BENCHMARK_CAPTURE(search_in_sorted_vector, binary, lower_bound);

BENCHMARK_CAPTURE(search_in_sorted_vector, linear, find);
```

`BENCHMARK_CAPTURE`宏接受函数、名称后缀和任意数量的参数。如果我们需要更多，我们可以在这里传递它们。我们的基准函数可以是常规函数或模板-两者都受支持。现在让我们看看在运行代码时我们会得到什么：

```cpp
-------------------------------------------------------------------------

Benchmark                               Time             CPU   Iterations

-------------------------------------------------------------------------

search_in_sorted_vector/binary       19.0 ns         18.5 ns     28000000

search_in_sorted_vector/linear        959 ns          952 ns       640000
```

如您所见，传递给函数的参数不是名称的一部分，而是函数名称和我们的后缀。

现在让我们看看如何进一步定制我们的基准测试。

### 将数值参数传递给微基准测试

设计类似我们的实验时的一个常见需求是在不同大小的参数上进行检查。在 Google Benchmark 中可以通过多种方式来满足这些需求。最简单的方法就是在`BENCHMARK`宏返回的对象上添加一个调用`Args()`。这样，我们可以传递一组值来在给定的微基准测试中使用。要使用传递的值，我们需要将我们的基准函数更改如下：

```cpp
void search_in_sorted_vector(benchmark::State &state, auto finder) {

  const auto haystack = make_sorted_vector<int>(state.range(0));

  const auto needle = 2137;

  for (auto _ : state) {

    benchmark::DoNotOptimize(finder(haystack, needle));

  }

}
```

对`state.range(0)`的调用将读取传递的第 0 个参数。可以支持任意数量。在我们的情况下，它用于参数化干草堆的大小。如果我们想要传递一系列值集合呢？这样，我们可以更容易地看到改变大小如何影响性能。我们可以调用`Range`而不是`Args`来进行基准测试：

```cpp
constexpr auto MIN_HAYSTACK_SIZE = std::size_t{1'000};

constexpr auto MAX_HAYSTACK_SIZE = std::size_t{10'000'000};


BENCHMARK_CAPTURE(search_in_sorted_vector, binary, lower_bound)

    ->RangeMultiplier(10)

    ->Range(MIN_HAYSTACK_SIZE, MAX_HAYSTACK_SIZE);

BENCHMARK_CAPTURE(search_in_sorted_vector, linear, find)

    ->RangeMultiplier(10)

    ->Range(MIN_HAYSTACK_SIZE, MAX_HAYSTACK_SIZE);
```

我们使用预定义的最小值和最大值来指定范围边界。然后我们告诉基准测试工具通过乘以 10 来创建范围，而不是使用默认值。当我们运行这样的基准测试时，可能会得到以下结果：

```cpp
-------------------------------------------------------------------------

Benchmark                                 Time        CPU     Iterations

-------------------------------------------------------------------------

search_in_sorted_vector/binary/1000      0.2 ns    19.9 ns     34461538

search_in_sorted_vector/binary/10000     24.8 ns   24.9 ns     26352941

search_in_sorted_vector/binary/100000    26.1 ns   26.1 ns     26352941

search_in_sorted_vector/binary/1000000   29.6 ns   29.5 ns     24888889

search_in_sorted_vector/binary/10000000  25.9 ns   25.7 ns     24888889

search_in_sorted_vector/linear/1000      482 ns     474 ns      1120000

search_in_sorted_vector/linear/10000     997 ns    1001 ns       640000

search_in_sorted_vector/linear/100000    1005 ns   1001 ns       640000

search_in_sorted_vector/linear/1000000   1013 ns   1004 ns       746667

search_in_sorted_vector/linear/10000000  990 ns    1004 ns       746667
```

在分析这些结果时，您可能会想知道为什么线性搜索没有显示出线性增长。这是因为我们寻找一个可以在恒定位置被发现的针的恒定值。如果干草堆中包含我们的针，我们需要相同数量的操作来找到它，无论干草堆的大小如何，因此执行时间停止增长（但仍可能受到小波动的影响）。

为什么不也尝试一下针的位置呢？

#### 以编程方式生成传递的参数

在一个简单的函数中生成干草堆大小和针位置可能是最简单的。Google Benchmark 允许这样的场景，让我们看看它们在实践中是如何工作的。

让我们首先重写我们的基准函数，以便在每次迭代中传递两个参数：

```cpp
void search_in_sorted_vector(benchmark::State &state, auto finder) {

  const auto needle = state.range(0);

  const auto haystack = make_sorted_vector<int>(state.range(1));

  for (auto _ : state) {

    benchmark::DoNotOptimize(finder(haystack, needle));

  }

}
```

如您所见，`state.range(0)`将标记我们的针位置，而`state.range(1)`将是干草堆的大小。这意味着我们需要每次传递两个值。让我们创建一个生成它们的函数：

```cpp
void generate_sizes(benchmark::internal::Benchmark *b) {

  for (long haystack = MIN_HAYSTACK_SIZE; haystack <= MAX_HAYSTACK_SIZE;

       haystack *= 100) {

    for (auto needle :

         {haystack / 8, haystack / 2, haystack - 1, haystack + 1}) {

      b->Args({needle, haystack});

    }

  }

}
```

我们不使用`Range`和`RangeMultiplier`，而是编写一个循环来生成干草堆的大小，这次每次增加 100。至于针，我们使用干草堆的成比例位置中的三个位置和一个落在干草堆之外的位置。我们在每次循环迭代中调用`Args`，传递生成的值。

现在，让我们将我们的生成函数应用于我们定义的基准测试：

```cpp
BENCHMARK_CAPTURE(search_in_sorted_vector, binary, lower_bound)->Apply(generate_sizes);

BENCHMARK_CAPTURE(search_in_sorted_vector, linear, find)->Apply(generate_sizes);
```

使用这样的函数可以轻松地将相同的生成器传递给许多基准测试。这样的基准测试可能的结果如下：

```cpp
-------------------------------------------------------------------------

Benchmark                                        Time     CPU  Iterations

-------------------------------------------------------------------------

search_in_sorted_vector/binary/125/1000       20.0 ns  20.1 ns   37333333

search_in_sorted_vector/binary/500/1000       19.3 ns  19.0 ns   34461538

search_in_sorted_vector/binary/999/1000       20.1 ns  19.9 ns   34461538

search_in_sorted_vector/binary/1001/1000      18.1 ns  18.0 ns   40727273

search_in_sorted_vector/binary/12500/100000   35.0 ns  34.5 ns   20363636

search_in_sorted_vector/binary/50000/100000   28.9 ns  28.9 ns   24888889

search_in_sorted_vector/binary/99999/100000   31.0 ns  31.1 ns   23578947

search_in_sorted_vector/binary/100001/100000  29.1 ns  29.2 ns   23578947

// et cetera
```

现在我们有了一个非常明确定义的实验来执行搜索。作为练习，在您自己的机器上运行实验，以查看完整的结果，并尝试从结果中得出一些结论。

### 选择微基准测试和优化的对象

进行这样的实验可能是有教育意义的，甚至会让人上瘾。但请记住，微基准测试不应该是项目中唯一的性能测试类型。正如唐纳德·克努斯所说：

*我们应该忘记小的效率，大约 97%的时间：过早的优化是万恶之源*

这意味着您应该只对重要的代码进行微基准测试，特别是您的热路径上的代码。较大的基准测试，以及跟踪和探测，可以用来查看何时何地进行优化，而不是猜测和过早优化。首先，了解您的软件是如何执行的。

注意：关于上面的引用，我们还想再提一个观点。这并不意味着您应该允许过早的*恶化*。数据结构或算法的选择不佳，甚至是散布在所有代码中的小的低效率，有时可能会影响系统的整体性能。例如，执行不必要的动态分配，虽然一开始看起来可能不那么糟糕，但随着时间的推移可能会导致堆碎片化，并在应用程序长时间运行时给您带来严重的麻烦。过度使用基于节点的容器也可能导致更多的缓存未命中。长话短说，如果编写高效代码而不是低效代码不需要花费太多精力，那就去做吧。

现在让我们学习一下，如果您的项目有需要长期保持良好性能的地方，应该怎么做。

### 使用基准测试创建性能测试

与精确测试的单元测试和代码正确性的大规模功能测试类似，您可以使用微基准测试和较大的基准测试来测试代码的性能。

如果对某些代码路径的执行时间有严格的限制，那么确保达到限制的测试可能非常有用。即使没有这样具体的限制，您可能也对监视性能在代码更改时如何变化感兴趣。如果在更改后，您的代码运行比以前慢了一定的阈值，测试可能会被标记为失败。

尽管也是一个有用的工具，但请记住，这样的测试容易受到渐渐降低性能的影响：随着时间的推移，性能的下降可能会不被注意，因此请确保偶尔监视执行时间。在您的 CI 中引入性能测试时，确保始终在相同的环境中运行，以获得稳定的结果。

现在让我们讨论性能工具箱中的下一类工具。

## 探测

虽然基准测试和跟踪可以为给定范围提供概述和具体数字，但探测器可以帮助您分析这些数字的来源。如果您需要深入了解性能并进行改进，它们是必不可少的工具。

### 选择要使用的探测器类型

有两种类型的探测器可用：仪器探测器和采样探测器。较为知名的仪器探测器之一是 Callgrind，它是 Valgrind 套件的一部分。仪器探测器有很大的开销，因为它们需要对您的代码进行仪器化，以查看您调用了哪些函数以及每个函数的执行时间。这样，它们产生的结果甚至包含最小的函数，但执行时间可能会受到这种开销的影响。它还有一个缺点，就是不总是能捕捉到输入/输出的缓慢和抖动。它会减慢执行速度，因此，虽然它可以告诉您调用特定函数的频率，但它不会告诉您缓慢是由于等待磁盘读取完成而引起的。

由于仪器探测器的缺陷，通常最好使用采样探测器。两个值得一提的是开源的 perf 用于在 Linux 系统上进行性能分析，以及英特尔的专有工具 VTune（对于开源项目是免费的）。虽然它们有时会由于采样的性质而错过关键事件，但通常应该能够更好地展示代码的时间分配情况。

如果你决定使用 perf，你应该知道你可以通过调用`perf stat`来使用它，这会给你一个关于 CPU 缓存使用等统计数据的快速概览，或者使用`perf record -g`和`perf report -g`来捕获和分析性能分析结果。

如果你想要对 perf 有一个扎实的概述，请观看 Chandler Carruth 的视频，其中展示了工具的可能性以及如何使用它，或者查看它的教程。这两者都在*进一步阅读*部分中链接。

### 准备分析器和处理结果

在分析性能分析结果时，你可能经常需要进行一些准备、清理和处理。例如，如果你的代码大部分时间都在忙碌，你可能希望将其过滤掉。在开始使用分析器之前，一定要编译或下载尽可能多的调试符号，包括你的代码、你的依赖项，甚至操作系统库和内核。此外，禁用帧指针优化也是必要的。在 GCC 和 Clang 上，你可以通过传递`-fno-omit-frame-pointer`标志来实现。这不会对性能产生太大影响，但会为你提供更多关于代码执行的数据。在结果的后处理方面，使用 perf 时，通常最好从结果中创建火焰图。Brendan Gregg 在*进一步阅读*部分中的工具非常适合这个用途。火焰图是一个简单而有效的工具，可以看出执行花费了太多时间的地方，因为图表上每个项目的宽度对应着资源使用情况。你可以得到 CPU 使用情况的火焰图，以及资源使用情况、分配和页面错误等方面的火焰图，或者代码在不执行时花费的时间，比如在系统调用期间保持阻塞、在互斥锁上、I/O 操作等。还有一些方法可以对生成的火焰图进行差异分析。

### 分析结果

请记住，并非所有性能问题都会在这样的图表上显示出来，也不是所有问题都可以通过性能分析器找到。尽管有了一些经验，你可能会发现你可以从为线程设置亲和性或更改线程在特定 NUMA 节点上执行的方式中受益，但并不总是那么明显地看出你忘记了禁用节能功能或者从启用或禁用超线程中受益。关于你运行的硬件的信息也是有用的。有时你可能会看到 CPU 的 SIMD 寄存器被使用，但代码仍然无法以最快的速度运行：你可能使用了 SSE 指令而不是 AVX 指令，AVX 而不是 AVX2，或者 AVX2 而不是 AVX512。当你分析性能分析结果时，了解你的 CPU 能够运行哪些具体指令可能是非常有价值的。

解决性能问题也需要一些经验。另一方面，有时经验可能会导致你做出错误的假设。例如，在许多情况下，使用动态多态性会影响性能；但也有一些情况下，它不会减慢你的代码。在得出结论之前，值得对代码进行性能分析，并了解编译器优化代码的各种方式以及这些技术的限制。具体来说，关于虚拟化，当你不希望其他类型继承和重写你的虚拟成员函数时，将你的虚拟成员函数的类标记为 final 通常会帮助编译器在许多情况下。

编译器也可以更好地优化，如果它们“看到”对象的类型：如果你在作用域中创建一个类型并调用它的虚拟成员函数，编译器应该能够推断出应该调用哪个函数。GCC 倾向于比其他编译器更好地进行去虚拟化。关于这一点的更多信息，你可以参考*进一步阅读*部分中 Arthur O'Dwyer 的博客文章。

与本节中介绍的其他类型的工具一样，尽量不要只依赖于您的分析器。性能分析结果的改进并不意味着您的系统变得更快。一个看起来更好的性能分析图仍然不能告诉您整个故事。一个组件的更好性能并不一定意味着整个系统的性能都得到了改善。这就是我们最后一种类型的工具可以派上用场的地方。

## 跟踪

我们将在本节中讨论的最后一种技术是针对分布式系统的。在查看整个系统时，通常部署在云中，在一个盒子上对软件进行性能分析并不能告诉您整个故事。在这种范围内，您最好的选择是跟踪请求和响应在系统中的流动。

跟踪是记录代码执行的一种方式。当一个请求（有时还有其响应）必须流经系统的许多部分时，通常会使用它。通常情况下，这样的消息会沿着路线被跟踪，并在执行的有趣点添加时间戳。

### 相关 ID

时间戳的一个常见补充是相关 ID。基本上，它们是分配给每个被跟踪消息的唯一标识符。它们的目的是在处理相同的传入请求期间（有时也是由此引起的事件），相关 ID 可以将系统的不同组件（如不同的微服务）产生的日志相关联起来。这样的 ID 应该随着消息一起传递，例如通过附加到其 HTTP 标头。即使原始请求已经消失，您也可以将其相关 ID 添加到每个响应中。

通过使用相关 ID，您可以跟踪给定请求的消息如何在系统中传播，以及系统的不同部分处理它所花费的时间。通常情况下，您还希望在途中收集额外的数据，例如用于执行计算的线程，为给定请求产生的响应的类型和数量，或者它经过的机器的名称。

像 Jaeger 和 Zipkin（或其他 OpenTracing 替代方案）这样的工具可以帮助您快速为系统添加跟踪支持。

现在让我们来处理一个不同的主题，并谈谈代码生成。

# 帮助编译器生成高性能代码

有许多方法可以帮助编译器为您生成高效的代码。有些方法归结为正确引导编译器，而其他方法则需要以对编译器友好的方式编写代码。

了解您在关键路径上需要做什么，并有效地设计它也很重要。例如，尽量避免虚拟分派（除非您可以证明它已被去虚拟化），并尽量不要在其中分配新内存。通常情况下，一切可能会降低性能的东西都应该保持在热路径之外。使指令和数据缓存都保持热度确实会产生回报。甚至像`[[likely]]`和`[[unlikely]]`这样的属性，可以提示编译器应该期望执行哪个分支，有时也会产生很大的变化。

## 优化整个程序

增加许多 C++项目性能的一个有趣方法是启用**链接时优化**（**LTO**）。在编译过程中，您的编译器不知道代码将如何与其他目标文件或库链接。许多优化的机会只有在这一点上才会出现：在链接时，您的工具可以看到程序的各个部分如何相互交互的整体情况。通过启用 LTO，您有时可以在几乎没有成本的情况下获得显著的性能改进。在 CMake 项目中，您可以通过设置全局的`CMAKE_INTERPROCEDURAL_OPTIMIZATION`标志或在目标上设置`INTERPROCEDURAL_OPTIMIZATION`属性来启用 LTO。

使用 LTO 的一个缺点是它使构建过程变得更长。有时会长很多。为了减少开发人员的成本，您可能只想为需要性能测试或发布的构建启用此优化。

## 基于实际使用模式进行优化

优化代码的另一种有趣方法是使用**基于配置文件的优化**（**PGO**）。这种优化实际上是一个两步过程。在第一步中，您需要使用额外的标志编译代码，导致可执行文件在运行时收集特殊的分析信息。然后，您应该在预期的生产负载下执行它。完成后，您可以使用收集的数据第二次编译可执行文件，这次传递不同的标志，指示编译器使用收集的数据生成更适合您的配置文件的代码。这样，您将得到一个准备好并调整到您特定工作负载的二进制文件。

## 编写友好缓存的代码

这两种优化技术都可以派上用场，但在处理高性能系统时，还有一件重要的事情需要牢记：缓存友好性。使用平面数据结构而不是基于节点的数据结构意味着您在运行时需要执行更少的指针追踪，这有助于提高性能。无论是向前还是向后读取，使用内存中连续的数据意味着您的 CPU 内存预取器可以在使用之前加载它，这通常会产生巨大的差异。基于节点的数据结构和上述指针追踪会导致随机内存访问模式，这可能会“混淆”预取器，并使其无法预取正确的数据。

如果您想查看一些性能结果，请参考* C++容器基准测试*中的链接。它比较了`std::vector`，`std::list`，`std::deque`和`plf::colony`的各种使用场景。如果你不知道最后一个，它是一个有趣的“袋”类型容器，具有快速插入和删除大数据的功能。

在选择关联容器时，您通常会希望使用“平面”实现而不是基于节点的实现。这意味着您可能想尝试`tsl::hopscotch_map`或 Abseil 的`flat_hash_map`和`flat_hash_set`，而不是使用`std::unordered_map`和`std::unordered_set`。

诸如将较冷的指令（例如异常处理代码）放在非内联函数中的技术可以帮助增加指令缓存的热度。这样，用于处理罕见情况的冗长代码将不会加载到指令缓存中，为应该在那里的更多代码留出空间，这也可以提高性能。

## 以数据为中心设计您的代码

如果要帮助缓存，另一种有用的技术是数据导向设计。通常，将更频繁使用的成员存储在内存中靠近彼此的位置是一个好主意。较冷的数据通常可以放在另一个结构中，并通过 ID 或指针与较热的数据连接。

有时，与更常见的对象数组不同，使用数组对象可以获得更好的性能。不要以面向对象的方式编写代码，而是将对象的数据成员分布在几个数组中，每个数组包含多个对象的数据。换句话说，采用以下代码：

```cpp
struct Widget {

    Foo foo;

    Bar bar;

    Baz baz;

};


auto widgets = std::vector<Widget>{};
```

并考虑用以下内容替换它：

```cpp
struct Widgets {

    std::vector<Foo> foos;

    std::vector<Bar> bars;

    std::vector<Baz> bazs;

};
```

这样，当处理一组特定的数据点与一些对象时，缓存热度增加，性能也会提高。如果你不知道这是否会提高代码的性能，请进行测量。

有时候，甚至重新排列类型的成员也可以带来更好的性能。您应该考虑数据成员类型的对齐。如果性能很重要，通常最好的做法是对它们进行排序，以便编译器不需要在成员之间插入太多填充。由于这样，您的数据类型的大小可以更小，因此许多这样的对象可以适应一个缓存行。考虑以下示例（假设我们正在为 x86_64 架构编译）：

```cpp
struct TwoSizesAndTwoChars {
    std::size_t first_size;
    char first_char;
    std::size_t second_size;
    char second_char;
};
static_assert(sizeof(TwoSizesAndTwoChars) == 32);
```

尽管每个大小都是 8 字节，每个字符只有 1 字节，但我们最终总共得到 32 字节！这是因为`second_size`必须从 8 字节对齐地址开始，所以在`first_char`之后，我们得到 7 字节的填充。对于`second_char`也是一样，因为类型需要相对于它们最大的数据类型成员进行对齐。

我们能做得更好吗？让我们尝试交换成员的顺序：

```cpp
struct TwoSizesAndTwoChars {
    std::size_t first_size;
    std::size_t second_size;
    char first_char;
    char second_char;
};
static_assert(sizeof(TwoSizesAndTwoChars) == 24);
```

通过简单地将最大的成员放在最前面，我们能够将结构的大小减小 8 字节，这占其大小的 25%。对于这样一个微不足道的改变来说，效果不错。如果您的目标是将许多这样的结构打包到连续的内存块中并对它们进行迭代，您可能会看到代码片段的性能大幅提升。

现在让我们谈谈另一种提高性能的方法。

# 并行计算

在这一部分，我们将讨论几种不同的并行计算方法。我们将从线程和进程之间的比较开始，然后向您展示 C++标准中可用的工具，最后但并非最不重要的是，我们将简要介绍 OpenMP 和 MPI 框架。

在我们开始之前，让我们简要介绍一下如何估计您可以从并行化代码中获得的最大可能收益。有两个定律可以帮助我们。第一个是 Amdahl 定律。它指出，如果我们想通过增加核心数来加速我们的程序，那么必须保持顺序执行的代码部分（无法并行化）将限制我们的可伸缩性。例如，如果您的代码有 90%是可并行化的，那么即使有无限的核心，您最多只能获得 10 倍的加速。即使我们将执行该 90%的时间缩短到零，这 10%的代码仍将始终存在。

第二定律是 Gustafson 定律。它指出，每个足够大的任务都可以有效地并行化。这意味着通过增加问题的规模，我们可以获得更好的并行化（假设我们有空闲的计算资源可用）。换句话说，有时候最好的方法是在相同的时间框架内增加更多的功能，而不是试图减少现有代码的执行时间。如果您可以通过将核心数量翻倍来将任务的时间减少一半，那么在某个时刻，再次翻倍核心数量将会带来递减的回报，因此它们的处理能力可以更好地用在其他地方。

## 了解线程和进程之间的区别

要有效地并行计算，您还需要了解何时使用进程执行计算，何时线程是更好的工具。长话短说，如果您的唯一目标是实际并行化工作，那么最好是从增加额外线程开始，直到它们不带来额外的好处为止。在这一点上，在您的网络中的其他机器上添加更多进程，每个进程也有多个线程。

为什么呢？因为进程比线程更加笨重。生成一个进程和在它们之间切换所需的时间比创建和在线程之间切换所需的时间更长。每个进程都需要自己的内存空间，而同一进程内的线程共享它们的内存。此外，进程间通信比在线程之间传递变量要慢。使用线程比使用进程更容易，因此开发速度也会更快。

然而，在单个应用程序范围内，进程也有其用途。它们非常适合隔离可以独立运行和崩溃而不会将整个应用程序一起崩溃的组件。拥有单独的内存也意味着一个进程无法窥视另一个进程的内存，这在您需要运行可能是恶意的第三方代码时非常有用。这两个原因是它们在 Web 浏览器等应用程序中使用的原因。除此之外，还可以以不同的操作系统权限或特权运行不同的进程，这是无法通过多个线程实现的。

现在让我们讨论一种在单台机器范围内并行化工作的简单方法。

## 使用标准并行算法

如果您执行的计算可以并行化，有两种方法可以利用这一点。一种是用可并行化的标准库算法替换您对常规调用。如果您不熟悉并行算法，它们是在 C++17 中添加的，在本质上是相同的算法，但您可以向每个算法传递执行策略。有三种执行策略：

+   `std::execution::seq`：用于以非并行化方式执行算法的顺序策略。这个我们也太熟悉了。

+   `std::execution::par`：一个并行策略，表示执行*可能*是并行的，通常在底层使用线程池。

+   `std::execution::par_unseq`：一个并行策略，表示执行*可能*是并行化和矢量化的。

+   `std::execution::unseq`：C++20 添加到该系列的一个策略。该策略表示执行可以矢量化，但不能并行化。

如果前面的策略对您来说还不够，标准库实现可能会提供其他策略。可能的未来添加可能包括用于 CUDA、SyCL、OpenCL 甚至人工智能处理器的策略。

现在让我们看看并行算法的实际应用。例如，要以并行方式对向量进行排序，您可以编写以下内容：

```cpp
std::sort(std::execution::par, v.begin(), v.end());
```

简单又容易。虽然在许多情况下这将产生更好的性能，但在某些情况下，您最好以传统方式执行算法。为什么？因为在更多线程上调度工作需要额外的工作和同步。此外，根据您的应用程序架构，它可能会影响其他已经存在的线程的性能并刷新它们的核心数据缓存。一如既往，先进行测量。

## 使用 OpenMP 和 MPI 并行化计算

使用标准并行算法的替代方法是利用 OpenMP 的编译指示。它们是一种通过添加几行代码轻松并行化许多类型计算的方法。如果您想要在集群上分发代码，您可能想看看 MPI 能为您做些什么。这两者也可以结合在一起。

使用 OpenMP，您可以使用各种编译指示轻松并行化代码。例如，您可以在`for`循环之前写`#pragma openmp parallel for`以使用并行线程执行它。该库还可以执行更多操作，例如在 GPU 和其他加速器上执行计算。

将 MPI 集成到您的项目中比只添加适当的编译指示更难。在这里，您需要在代码库中使用 MPI API 在进程之间发送或接收数据（使用诸如`MPI_Send`和`MPI_Recv`的调用），或执行各种聚合和减少操作（调用`MPI_Bcast`和`MPI_Reduce`等此类函数）。通信可以通过点对点或使用称为通信器的对象到所有集群进行。

根据您的算法实现，MPI 节点可以全部执行相同的代码，或者在需要时可以变化。节点将根据其等级知道它应该如何行为：在计算开始时分配的唯一编号。说到这一点，要使用 MPI 启动进程，您应该通过包装器运行它，如下所示：

```cpp
$ mpirun --hostfile my_hostfile -np 4 my_command --with some ./args
```

这将逐个从文件中读取主机，连接到每个主机，并在每个主机上运行四个`my_command`实例，传递参数。

MPI 有许多实现。其中最值得注意的是 OpenMPI（不要将其与 OpenMP 混淆）。在一些有用的功能中，它提供了容错能力。毕竟，节点宕机并不罕见。

我们想在本节中提到的最后一个工具是 GNU Parallel，如果您想要轻松地生成并行进程来执行工作，那么您可能会发现它很有用。它既可以在单台机器上使用，也可以跨计算集群使用。

说到执行代码的不同方式，现在让我们讨论 C++20 中的另一个重要主题：协程。

# 使用协程

协程是可以暂停其执行并稍后恢复的函数。它们允许以非常类似于编写同步代码的方式编写异步代码。与使用`std::async`编写异步代码相比，这允许编写更清晰、更易于理解和维护的代码。不再需要编写回调函数，也不需要处理`std::async`的冗长性与 promise 和 future。

除此之外，它们通常还可以为您提供更好的性能。基于`std::async`的代码通常在切换线程和等待方面有更多的开销。协程可以非常廉价地恢复和暂停，甚至与调用函数的开销相比，这意味着它们可以提供更好的延迟和吞吐量。此外，它们的设计目标之一是高度可扩展，甚至可以扩展到数十亿个并发协程。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/sw-arch-cpp/img/527abf17-78b4-4414-aa38-5bd846f4d1c4.png)

图 11.1 - 调用和执行协程与使用常规函数不同，因为它们可以被暂停和恢复

C++协程是无栈的，这意味着它们的状态不存储在调用线程的堆栈上。这使它们具有一个有趣的特性：几个不同的线程可以接管协程的执行。换句话说，即使看起来协程函数体将按顺序执行，其中的部分也可以在不同的线程中执行。这使得可以将函数的部分留给专用线程来执行。例如，I/O 操作可以在专用的 I/O 线程中完成。

要检查一个函数是否是 C++协程，需要在其主体中查找以下关键字之一：

+   `co_await`，暂停协程。

+   `co_yield`，将一个值返回给调用者并暂停协程。类似于 Python 中生成器中使用的`yield`关键字。允许惰性生成值。

+   `co_return`，返回一个值并结束执行协程。这是`return`关键字的协程等价物。

每当函数主体具有这些关键字之一时，该函数自动成为协程。虽然这意味着这是一个实现细节，但还有一个提示可以使用：协程返回类型必须满足某些要求，我们将在后面讨论。

协程在 C++世界中是一等公民。这意味着你可以获得它们的地址，将它们用作函数参数，从函数中返回它们，并将它们存储在对象中。

在 C++中，即使在 C++20 之前，你也可以编写协程。这得益于诸如 Boost.Coroutine2 或 Bloomberg 的 Quantum 等库。后者甚至被用来实现 CoroKafka - 一个使用协程高效处理 Kafka 流的库。随着标准 C++协程的出现，新的库开始出现。现在，我们将向您展示其中之一。

## 区分 cppcoro 实用程序

从头开始编写基于协程的代码很困难。C++20 只提供了编写协程的基本实用程序，因此在编写自己的协程时，我们需要一组原语来使用。由 Lewis Baker 创建的 cppcoro 库是 C++中最常用的协程框架之一。在本节中，我们将展示该库，并演示在编写基于协程的代码时如何使用它。

让我们从库提供的协程类型概述开始：

+   `任务<>`：用于安排稍后执行的工作-当它被`co_awaited`时开始执行。

+   `shared_task<>`：多个协程可以等待的任务。它可以被复制，以便多个协程引用相同的结果。本身不提供任何线程安全性。

+   `generator`：惰性和同步地产生一系列 Ts。它实际上是一个`std::range`：它有一个返回迭代器的`begin()`和一个返回哨兵的`end()`。

+   `recursive_generator`：类似于`generator<T>`，但可以产生 T 或`recursive_generator<T>`。有一些额外的开销。

+   `async_generator`：类似于`generator<T>`，但值可以异步产生。这意味着与生成器相反，异步生成器可以在其主体中使用`co_await`。

您应该将这些类型用作协程的返回类型。通常，在您的生成器（返回前述生成器类型之一的协程）中，您希望使用`co_yield`返回值（类似于 Python 生成器）。但是，在您的任务中，通常，您将希望使用`co_await`安排工作。

该库实际上提供了许多编程抽象，不仅仅是前述的协程类型。它还提供以下类型：

+   **可等待对象**可以在其上`co_await`的类型，例如协程风格的事件和同步原语：互斥锁、闩锁、屏障等。

+   **与取消相关的实用程序**，基本上允许您取消协程的执行。

+   **调度程序**-允许您通过它们安排工作的对象，例如`static_thread_pool`，或者用于在特定线程上安排工作的对象。

+   **I/O 和网络实用程序**，允许您从文件和 IP 套接字中读取和写入。

+   **元函数和概念**，例如`awaitable_traits`、`Awaitable`和`Awaiter`。

除了前述的实用程序之外，cppcoro 还为我们提供了函数-用于使用其他类和引导执行的实用程序，例如以下内容：

+   `sync_wait`：阻塞，直到传递的可等待对象完成。

+   `when_all, when_all_ready`：返回一个可等待对象，当所有传递的可等待对象完成时完成。这两者之间的区别在于处理子可等待对象的失败。`when_all_ready`将在发生故障时完成，调用者可以检查每个结果，而`when_all`将重新抛出异常，如果任何子可等待对象抛出异常（尽管不可能知道哪个子对象抛出异常）。它还将取消任何未完成的任务。

+   `fmap`：类似于函数式编程，将函数应用于可等待对象。您可以将其视为将一种类型的任务转换为另一种类型的任务。例如，您可以通过调用`fmap(serialize, my_coroutine())`序列化由您的协程返回的类型。

+   `resume_on`：指示协程在完成某些工作后继续执行时使用哪个调度程序。这使您能够在特定的执行上下文中执行某些工作，例如在专用 I/O 线程上运行 I/O 相关的任务。请注意，这意味着单个 C++函数（协程）可以在不同的线程上执行其部分。可以类似于`std::ranges`一样与计算一起“管道化”。

+   `schedule_on`：指示协程使用哪个调度程序开始一些工作。通常用作`auto foo = co_await schedule_on(scheduler, do_work());`。

在我们开始一起使用这些实用程序之前，让我们再说几句关于可等待对象。

## 查看可等待对象和协程的内部工作原理

除了 cppcoro 之外，标准库还提供了另外两个简单的可等待对象：`suspend_never`和`suspend_always`。通过查看它们，我们可以看到在需要时如何实现我们自己的可等待对象：

```cpp
struct suspend_never {

    constexpr bool await_ready() const noexcept { return true; }

    constexpr void await_suspend(coroutine_handle<>) const noexcept {}

    constexpr void await_resume() const noexcept {}

};


struct suspend_always {

    constexpr bool await_ready() const noexcept { return false; }

    constexpr void await_suspend(coroutine_handle<>) const noexcept {}

    constexpr void await_resume() const noexcept {}

};
```

当输入`co_await`时，您告诉编译器首先调用等待器的`await_ready()`。如果它通过返回 true 表示等待器已准备就绪，将调用`await_resume()`。`await_resume()`的返回类型应该是等待器实际产生的类型。如果等待器没有准备好，程序将执行`await_suspend()`。完成后，我们有三种情况：

+   `await_suspend`返回`void`：执行后总是会暂停。

+   `await_suspend`返回`bool`：根据返回的值，执行将暂停或不暂停。

+   `await_suspend`返回`std::coroutine_handle<PromiseType>`：另一个协程将被恢复。

协程底层有更多的东西。即使协程不使用`return`关键字，编译器也会在底层生成代码使它们编译和工作。当使用`co_yield`等关键字时，它会将它们重写为对应的辅助类型的成员函数的调用。例如，对`co_yield x`的调用等效于`co_await` `promise.yield_value(x)`。如果您想了解更多关于发生了什么并编写自己的协程类型，请参考*进一步阅读*部分的*Your First Coroutine*文章。

好的，现在让我们利用所有这些知识来编写我们自己的协程。我们将创建一个简单的应用程序，模拟进行有意义的工作。它将使用线程池来填充一个向量中的一些数字。

我们的 CMake 目标将如下所示：

```cpp
add_executable(coroutines_1 coroutines/main_1.cpp)

target_link_libraries(coroutines_1 PRIVATE cppcoro fmt::fmt Threads::Threads)

target_compile_features(coroutines_1 PRIVATE cxx_std_20)
```

我们将链接到 cppcoro 库。在我们的情况下，我们使用 Andreas Buhr 的 cppcoro 分支，因为它是 Lewis Baker 存储库的一个维护良好的分支，并支持 CMake。

我们还将链接到优秀的`{fmt}`库进行文本格式化。如果您的标准库提供了 C++20 的字符串格式化，您也可以使用它。

最后但同样重要的是，我们需要一个线程库 - 毕竟，我们想要在池中使用多个线程。

让我们从一些常量和一个`main`函数开始我们的实现：

```cpp
inline constexpr auto WORK_ITEMS = 5;


int main() {

  auto thread_pool = cppcoro::static_thread_pool{3};
```

我们希望使用三个池化线程生成五个项目。cppcoro 的线程池是一种很好的调度工作的方式。默认情况下，它会创建与您的机器硬件线程一样多的线程。继续前进，我们需要指定我们的工作：

```cpp
  fmt::print("Thread {}: preparing work\n", std::this_thread::get_id());

  auto work = do_routine_work(thread_pool);


  fmt::print("Thread {}: starting work\n", std::this_thread::get_id());

  const auto ints = cppcoro::sync_wait(work);
```

我们将在代码中添加日志消息，以便您更好地了解在哪个线程中发生了什么。这将帮助我们更好地理解协程的工作原理。我们通过调用名为`do_routine_work`的协程来创建工作。它返回给我们协程，我们使用`sync_wait`阻塞函数来运行它。协程在实际被等待之前不会开始执行。这意味着我们的实际工作将在这个函数调用内开始执行。

一旦我们有了结果，让我们记录它们：

```cpp
  fmt::print("Thread {}: work done. Produced ints are: ",

             std::this_thread::get_id());

  for (auto i : ints) {

    fmt::print("{}, ", i);

  }

  fmt::print("\n");
```

这里没有巫术魔法。让我们定义我们的`do_routine_work`协程：

```cpp
cppcoro::task<std::vector<int>>

do_routine_work(cppcoro::static_thread_pool &thread_pool) {


  auto mutex = cppcoro::async_mutex{};

  auto ints = std::vector<int>{};

  ints.reserve(WORK_ITEMS);
```

它返回一个任务，产生一些整数。因为我们将使用线程池，让我们使用 cppcoro 的`async_mutex`来同步线程。现在让我们开始使用池：

```cpp
  fmt::print("Thread {}: passing execution to the pool\n",

             std::this_thread::get_id());


  co_await thread_pool.schedule();
```

您可能会感到惊讶，`schedule()`调用没有传入任何可调用对象来执行。在协程的情况下，我们实际上是让当前线程挂起协程并开始执行其调用者。这意味着它现在将等待协程完成（在`sync_wait`调用中的某个地方）。

与此同时，来自我们池中的一个线程将恢复协程 - 简单地继续执行其主体。这是我们为它准备的：

```cpp
  fmt::print("Thread {}: running first pooled job\n",

             std::this_thread::get_id());


  std::vector<cppcoro::task<>> tasks;

  for (int i = 0; i < WORK_ITEMS; ++i) {

    tasks.emplace_back(

        cppcoro::schedule_on(thread_pool, fill_number(i, ints, mutex)));

  }

  co_await cppcoro::when_all_ready(std::move(tasks));
  co_return ints;
```

我们创建一个要执行的任务向量。每个任务在互斥锁下填充`ints`中的一个数字。`schedule_on`调用使用我们池中的另一个线程运行填充协程。最后，我们等待所有的结果。此时，我们的任务开始执行。最后，由于我们的协程是一个任务，我们使用`co_return`。

不要忘记使用`co_return`返回生成的值。如果我们从示例中删除了`co_return ints;`这一行，我们将简单地返回一个默认构造的向量。程序将运行，愉快地打印空向量，并以代码 0 退出。

我们的最后一步是实现一个将产生一个数字的协程：

```cpp
cppcoro::task<> fill_number(int i, std::vector<int> &ints,

                            cppcoro::async_mutex &mutex) {

  fmt::print("Thread {}: producing {}\n", std::this_thread::get_id(), i);

  std::this_thread::sleep_for(

      std::chrono::milliseconds((WORK_ITEMS - i) * 200));
```

这是一个不返回任何值的任务。相反，它将其添加到我们的向量中。它的辛苦工作实际上是通过打盹一定数量的毫秒来完成的。醒来后，协程将继续进行更有成效的努力：

```cpp
  {

    auto lock = co_await mutex.scoped_lock_async();

    ints.emplace_back(i);

  }
```

它将锁定互斥锁。在我们的情况下，它只是一个`await`。当互斥锁被锁定时，它将向我们的向量添加一个数字 - 与调用它的相同的数字。

注意：记得使用`co_await`。如果你忘记了，而你的可等待对象允许这样做（也许是因为可以不消耗每个可等待对象），那么你可能会跳过一些重要的计算。在我们的示例中，这可能意味着不锁定互斥锁。

让我们现在完成协程的实现：

```cpp
  fmt::print("Thread {}: produced {}\n", std::this_thread::get_id(), i);

  co_return;
```

只是一个简单的`status print`和一个`co_return`来标记协程为完成。一旦返回，协程帧就可以被销毁，释放其占用的内存。

就这些了。现在让我们运行我们的代码，看看会发生什么：

```cpp
Thread 140471890347840: preparing work

Thread 140471890347840: starting work

Thread 140471890347840: passing execution to the pool

Thread 140471890282240: running first pooled job

Thread 140471890282240: producing 4

Thread 140471881828096: producing 1

Thread 140471873373952: producing 0

Thread 140471890282240: produced 4

Thread 140471890282240: producing 3

Thread 140471890282240: produced 3

Thread 140471890282240: producing 2

Thread 140471881828096: produced 1

Thread 140471873373952: produced 0

Thread 140471890282240: produced 2

Thread 140471890347840: work done. Produced ints are: 4, 3, 1, 0, 2, 
```

我们的主线程用于在线程池上启动工作，然后等待结果。然后，我们的线程池中的三个线程正在生成数字。最后安排的任务实际上是第一个运行的任务，生成数字 4。这是因为它一直在执行`do_routine_work`：首先，在线程池上安排了所有其他任务，然后在调用`when_all_ready`时开始执行第一个任务。随后，执行继续进行，第一个空闲线程接管线程池上安排的下一个任务，直到整个向量填满。最后，执行返回到我们的主线程。

这就结束了我们的简短示例。随之而来的是本章的最后一节。现在让我们总结一下我们学到的东西。

# 总结

在本章中，我们学习了什么类型的工具可以帮助我们提高代码的性能。我们学习了如何进行实验，编写性能测试，并寻找性能瓶颈。您现在可以使用 Google Benchmark 编写微基准测试。此外，我们讨论了如何对代码进行性能分析，以及如何（以及为什么）实现系统的分布式跟踪。我们还讨论了如何使用标准库工具和外部解决方案并行化计算。最后但同样重要的是，我们向您介绍了协程。您现在知道 C++20 为协程带来了什么，以及您可以在 cppcoro 库中找到什么。您还学会了如何编写自己的协程。

本章最重要的教训是：在性能方面，先进行测量，后进行优化。这将帮助您最大限度地发挥您的工作影响。

这就是性能 - 我们想在书中讨论的最后一个质量属性。在下一章中，我们将开始进入服务和云的世界。我们将首先讨论面向服务的架构。

# 问题

1.  我们从本章微基准测试的性能结果中可以学到什么？

1.  遍历多维数组对性能重要吗？为什么/为什么不？

1.  在我们的协程示例中，为什么不能在`do_routine_work`函数内创建线程池？

1.  我们如何重新设计我们的协程示例，使其使用生成器而不仅仅是任务？

# 进一步阅读

+   C++编译器何时可以进行虚函数调用优化？，博客文章，Arthur O'Dwyer，[`quuxplusone.github.io/blog/2021/02/15/devirtualization/`](https://quuxplusone.github.io/blog/2021/02/15/devirtualization/)

+   CppCon 2015: Chandler Carruth "Tuning C++: Benchmarks, and CPUs, and Compilers! Oh My!"，YouTube 视频，[`www.youtube.com/watch?v=nXaxk27zwlk`](https://www.youtube.com/watch?v=nXaxk27zwlk)

+   教程，Perf Wiki，[`perf.wiki.kernel.org/index.php/Tutorial`](https://perf.wiki.kernel.org/index.php/Tutorial)

+   CPU Flame Graphs，Brendan Gregg，[`www.brendangregg.com/FlameGraphs/cpuflamegraphs.html`](http://www.brendangregg.com/FlameGraphs/cpuflamegraphs.html)

+   C++ 容器基准测试，Baptiste Wicht 的博客文章，[`baptiste-wicht.com/posts/2017/05/cpp-containers-benchmark-vector-list-deque-plf-colony.html`](https://baptiste-wicht.com/posts/2017/05/cpp-containers-benchmark-vector-list-deque-plf-colony.html)

+   你的第一个协程，Dawid Pilarski 的博客文章，[`blog.panicsoftware.com/your-first-coroutine`](https://blog.panicsoftware.com/your-first-coroutine)


# 第四部分：云原生设计原则

本节重点介绍了起源于分布式系统和云环境的现代架构风格。它展示了诸如面向服务的架构、包括容器在内的微服务，以及各种消息系统等概念。

本节包含以下章节：

+   [第十二章]，*面向服务的架构*

+   [第十三章]，*设计微服务*

+   [第十四章]，*容器*

+   [第十五章]，*云原生设计*


# 第十二章：面向服务的架构

分布式系统的一个非常常见的架构是**面向服务的架构**（**SOA**）。这不是一个新的发明，因为这种架构风格几乎和计算机网络一样古老。SOA 有许多方面，从**企业服务总线**（**ESB**）到云原生微服务。

如果您的应用程序包括 Web、移动或**物联网**（**IoT**）接口，本章将帮助您了解如何以模块化和可维护性为重点构建它们。由于大多数当前系统以客户端-服务器（或其他网络拓扑）方式工作，学习 SOA 原则将帮助您设计和改进这样的系统。

本章将涵盖以下主题：

+   理解 SOA

+   采用消息传递原则

+   使用 Web 服务

+   利用托管服务和云提供商

# 技术要求

本章中提出的大多数示例不需要任何特定的软件。对于 AWS API 示例，您将需要**AWS SDK for C++**，可以在[`aws.amazon.com/sdk-for-cpp/`](https://aws.amazon.com/sdk-for-cpp/)找到。

本章中的代码已放在 GitHub 上，网址为[`github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter12`](https://github.com/PacktPublishing/Software-Architecture-with-Cpp/tree/master/Chapter12)。

# 理解面向服务的架构

面向服务的架构是一个特征松散耦合的组件提供服务给彼此的软件设计的例子。这些组件使用共享的通信协议，通常是通过网络。在这种设计中，服务意味着可以在原始组件之外访问的功能单元。一个组件的例子可能是一个提供地理坐标响应区域地图的映射服务。

根据定义，服务具有四个属性：

+   它是业务活动的一种表现，具有明确定义的结果。

+   它是自包含的。

+   它对用户是不透明的。

+   它可能由其他服务组成。

## 实施方法

面向服务的架构并不规定如何处理服务定位。这是一个可以应用于许多不同实现的术语。关于一些方法是否应该被视为面向服务的架构存在讨论。我们不想参与这些讨论，只是强调一些经常被提及为 SOA 方法的方法。

让我们比较一些。

### 企业服务总线

当有人提到面向服务的架构时，ESB 往往是第一个联想到的。这是实现 SOA 的最古老方法之一。

ESB 从计算机硬件架构中得到类比。硬件架构使用计算机总线，如 PCI，以实现模块化。这样，第三方提供商可以独立于主板制造商实现模块（如图形卡、声卡或 I/O 接口），只要每个人都遵守总线所需的标准。

与 PCI 类似，ESB 架构旨在构建一种标准的通用方式，以允许松散耦合服务的交互。这些服务预计将独立开发和部署。还应该可以组合异构服务。

与 SOA 本身一样，ESB 没有由任何全局标准定义。要实现 ESB，需要在系统中建立一个额外的组件。这个组件就是总线本身。ESB 上的通信是事件驱动的，通常是通过消息导向中间件和消息队列实现的，我们将在后面的章节中讨论。

企业服务总线组件扮演以下角色：

+   控制服务的部署和版本控制

+   维护服务冗余

+   在服务之间路由消息

+   监控和控制消息交换

+   解决组件之间的争执

+   提供常见服务，如事件处理、加密或消息队列

+   强制服务质量（**QOS**）

既有专有商业产品，也有实现企业服务总线功能的开源产品。一些最受欢迎的开源产品如下：

+   Apache Camel

+   Apache ServiceMix

+   Apache Synapse

+   JBoss ESB

+   OpenESB

+   Red Hat Fuse（基于 Apache Camel）

+   Spring 集成

最受欢迎的商业产品如下：

+   IBM 集成总线（取代 IBM WebSphere ESB）

+   Microsoft Azure 服务总线

+   Microsoft BizTalk Server

+   Oracle 企业服务总线

+   SAP 过程集成

与本书中介绍的所有模式和产品一样，您在决定采用特定架构之前，必须考虑其优势和劣势。引入企业服务总线的一些好处如下：

+   更好的服务可扩展性

+   分布式工作负载

+   可以专注于配置而不是在服务中实现自定义集成

+   设计松散耦合服务的更简单方法

+   服务是可替换的

+   内置冗余能力

另一方面，缺点主要围绕以下方面：

+   单点故障-ESB 组件的故障意味着整个系统的故障。

+   配置更复杂，影响维护。

+   消息队列、消息转换以及 ESB 提供的其他服务可能会降低性能甚至成为瓶颈。

### Web 服务

Web 服务是面向服务的架构的另一种流行实现。根据其定义，Web 服务是一台机器向另一台机器（或操作者）提供的服务，通信是通过万维网协议进行的。尽管万维网的管理机构 W3C 允许使用 FTP 或 SMTP 等其他协议，但 Web 服务通常使用 HTTP 作为传输协议。

虽然可以使用专有解决方案实现 Web 服务，但大多数实现都基于开放协议和标准。尽管许多方法通常被称为 Web 服务，但它们在本质上是不同的。稍后在本章中，我们将详细描述各种方法。现在，让我们专注于它们的共同特点。

#### Web 服务的优缺点

Web 服务的好处如下：

+   使用流行的 Web 标准

+   大量的工具

+   可扩展性

以下是缺点：

+   大量开销。

+   一些实现过于复杂（例如 SOAP/WSDL/UDDI 规范）。

### 消息和流

在介绍企业服务总线架构时，我们已经提到了消息队列和消息代理。除了作为 ESB 实现的一部分外，消息系统也可以作为独立的架构元素。

#### 消息队列

消息队列是用于**进程间通信**（**IPC**）的组件。顾名思义，它们使用队列数据结构在不同进程之间传递消息。通常，消息队列是**面向消息的中间件**（**MOM**）设计的一部分。

在最低级别上，消息队列在 UNIX 规范中都有，包括 System V 和 POSIX。虽然它们在单台机器上实现 IPC 时很有趣，但我们想要专注于适用于分布式计算的消息队列。

目前在开源软件中有三种与消息队列相关的标准：

1.  **高级消息队列协议**（**AMQP**），一种在 7 层 OSI 模型的应用层上运行的二进制协议。流行的实现包括以下内容：

+   Apache Qpid

+   Apache ActiveMQ

+   RabbitMQ

+   Azure 事件中心

+   Azure 服务总线

1.  **流文本定向消息协议**（**STOMP**），一种类似于 HTTP 的基于文本的协议（使用诸如`CONNECT`、`SEND`、`SUBSCRIBE`等动词）。流行的实现包括以下内容：

+   Apache ActiveMQ

+   RabbitMQ

+   syslog-ng

1.  **MQTT**，一个面向嵌入式设备的轻量级协议。流行的实现包括以下家庭自动化解决方案：

+   OpenHAB

+   Adafruit IO

+   IoT Guru

+   Node-RED

+   Home Assistant

+   Pimatic

+   AWS IoT

+   Azure IoT Hub

#### 消息代理

消息代理处理消息系统中消息的翻译、验证和路由。与消息队列一样，它们是 MOM 的一部分。

使用消息代理，您可以最大程度地减少应用程序对系统其他部分的感知。这导致设计松散耦合的系统，因为消息代理承担了与消息上的常见操作相关的所有负担。这被称为**发布-订阅**（**PubSub**）设计模式。

代理通常管理接收者的消息队列，但也能执行其他功能，例如以下功能：

+   将消息从一种表示形式转换为另一种

+   验证消息发送者、接收者或内容

+   将消息路由到一个或多个目的地

+   聚合、分解和重组传输中的消息

+   从外部服务检索数据

+   通过与外部服务的交互增强和丰富消息

+   处理和响应错误和其他事件

+   提供不同的路由模式，如发布-订阅

消息代理的流行实现包括以下内容：

+   Apache ActiveMQ

+   Apache Kafka

+   Apache Qpid

+   Eclipse Mosquitto MQTT Broker

+   NATS

+   RabbitMQ

+   Redis

+   AWS ActiveMQ

+   AWS Kinesis

+   Azure Service Bus

### 云计算

云计算是一个广义的术语，有很多不同的含义。最初，**云**这个术语指的是架构不应该过于担心的抽象层。例如，这可能意味着由专门的运维团队管理的服务器和网络基础设施。后来，服务提供商开始将云计算这个术语应用到他们自己的产品上，这些产品通过抽象底层基础设施及其所有复杂性。不必单独配置每个基础设施部分，只需使用简单的**应用程序编程接口**（**API**）即可设置所有必要的资源。

如今，云计算已经发展到包括许多新颖的应用架构方法。它可能包括以下内容：

+   托管服务，如数据库、缓存层和消息队列

+   可扩展的工作负载编排

+   容器部署和编排平台

+   无服务器计算平台

考虑云采用时最重要的一点是，将应用程序托管在云中需要专门为云设计的架构。通常还意味着专门为特定云提供商设计的架构。

这意味着选择云提供商不仅仅是在某一时刻做出一个选择是否比另一个更好的决定。这意味着未来切换提供商的成本可能太大，不值得搬迁。在提供商之间迁移需要架构变更，对于一个正常运行的应用程序来说，这可能会超过迁移带来的预期节省。

云架构设计还有另一个后果。对于传统应用程序来说，这意味着为了利用云的好处，应用程序首先必须重新设计和重写。迁移到云并不仅仅是将二进制和配置文件从本地托管复制到由云提供商管理的虚拟机。这种方法只会意味着浪费金钱，因为只有当您的应用程序是可扩展的并且具备云意识时，云计算才是划算的。

云计算并不一定意味着使用外部服务并从第三方提供商租用机器。还有一些解决方案，比如运行在本地的 OpenStack，它允许您利用已经拥有的服务器来享受云计算的好处。

我们将在本章后面讨论托管服务。容器、云原生设计和无服务器架构将在本书的后面有专门的章节。

### 微服务

关于微服务是否属于 SOA 存在一些争议。大多数情况下，SOA 这个术语几乎等同于 ESB 设计。在许多方面，微服务与 ESB 相反。这导致了微服务是 SOA 的一个独特模式的观点，是软件架构演进的下一步。

我们认为，实际上，这些是一种现代的 SOA 方法，旨在消除 ESB 中出现的一些问题。毕竟，微服务非常符合面向服务的架构的定义。

微服务是下一章的主题。

## 面向服务的架构的好处

将系统的功能分割到多个服务中有几个好处。首先，每个服务可以单独维护和部署。这有助于团队专注于特定任务，而无需了解系统内的每种可能的交互。它还实现了敏捷开发，因为测试只需覆盖特定服务，而不是整个系统。

第二个好处是服务的模块化有助于创建分布式系统。通过网络（通常基于互联网协议）作为通信手段，服务可以分布在不同的机器之间，以提供可伸缩性、冗余性和更好的资源利用率。

当每个服务有许多生产者和许多消费者时，实施新功能和维护现有软件是一项困难的任务。这就是为什么 SOA 鼓励使用文档化和版本化的 API。

另一种使服务生产者和消费者更容易互动的方法是使用已建立的协议，描述如何在不同服务之间传递数据和元数据。这些协议可能包括 SOAP、REST 或 gRPC。

使用 API 和标准协议可以轻松创建提供超出现有服务的附加值的新服务。考虑到我们有一个返回地理位置的服务 A，另一个服务 B，它提供给定位置的当前温度，我们可以调用 A 并在请求 B 中使用其响应。这样，我们就可以获得当前位置的当前温度，而无需自己实现整个逻辑。

我们对这两个服务的所有复杂性和实现细节一无所知，并将它们视为黑匣子。这两个服务的维护者也可以引入新功能并发布新版本的服务，而无需通知我们。

测试和实验面向服务的架构也比单片应用更容易。单个地方的小改变不需要重新编译整个代码库。通常可以使用客户端工具以临时方式调用服务。

让我们回到我们的天气和地理位置服务的例子。如果这两个服务都暴露了 REST API，我们可以仅使用 cURL 客户端手动发送适当的请求来构建原型。当我们确认响应令人满意时，我们可以开始编写代码，自动化整个操作，并可能将结果公开为另一个服务。

要获得 SOA 的好处，我们需要记住所有服务都必须松散耦合。如果服务依赖于彼此的实现，这意味着它们不再是松散耦合，而是紧密耦合。理想情况下，任何给定的服务都应该可以被不同的类似服务替换，而不会影响整个系统的运行。

在我们的天气和位置示例中，这意味着在不同语言中重新实现位置服务（比如，从 Go 切换到 C++）不应影响该服务的下游消费者，只要他们使用已建立的 API。

通过发布新的 API 版本仍然可能引入 API 的破坏性变化。连接到 1.0 版本的客户端将观察到传统行为，而连接到 2.0 版本的客户端将受益于错误修复，更好的性能和其他改进，这些改进是以兼容性为代价的。

对于依赖 HTTP 的服务，API 版本通常发生在 URI 级别。因此，当调用[`service.local/v1/customer`](https://service.local/v1/customer)时，可以访问 1.0、1.1 或 1.2 版本的 API，而 2.0 版本的 API 位于[`service.local/v2/customer`](https://service.local/v2/customer)。然后，API 网关、HTTP 代理或负载均衡器能够将请求路由到适当的服务。

## SOA 的挑战

引入抽象层总是有成本的。同样的规则适用于面向服务的体系结构。当看到企业服务总线、Web 服务或消息队列和代理时，可以很容易地看到抽象成本。可能不太明显的是微服务也有成本。它们的成本与它们使用的远程过程调用（RPC）框架以及与服务冗余和功能重复相关的资源消耗有关。

与 SOA 相关的另一个批评目标是缺乏统一的测试框架。开发应用程序服务的个人团队可能使用其他团队不熟悉的工具。与测试相关的其他问题是组件的异构性和可互换性意味着有大量的组合需要测试。一些组合可能会引入通常不会观察到的边缘情况。

由于关于特定服务的知识大多集中在一个团队中，因此要理解整个应用程序的工作方式要困难得多。

当应用程序的 SOA 平台在应用程序的生命周期内开发时，可能会引入所有服务更新其版本以针对最新平台开发的需求。这意味着开发人员不再是引入新功能，而是专注于确保他们的应用程序在对平台进行更改后能够正确运行。在极端情况下，对于那些没有看到新版本并且不断修补以符合平台要求的服务，维护成本可能会急剧上升。

面向服务的体系结构遵循康威定律，详见第二章，*架构风格*。

# 采用消息传递原则

正如我们在本章前面提到的，消息传递有许多不同的用例，从物联网和传感器网络到在云中运行的基于微服务的分布式应用程序。

消息传递的好处之一是它是一种连接使用不同技术实现的服务的中立方式。在开发 SOA 时，每个服务通常由专门的团队开发和维护。团队可以选择他们感觉舒适的工具。这适用于编程语言、第三方库和构建系统。

维护统一的工具集可能会适得其反，因为不同的服务可能有不同的需求。例如，一个自助应用可能需要一个像 Qt 这样的图形用户界面（GUI）库。作为同一应用程序的一部分的硬件控制器将有其他要求，可能链接到硬件制造商的第三方组件。这些依赖关系可能会对不能同时满足两个组件的一些限制（例如，GUI 应用程序可能需要一个较新的编译器，而硬件对应可能被固定在一个较旧的编译器上）。使用消息系统来解耦这些组件让它们有单独的生命周期。

消息系统的一些用例包括以下内容：

+   金融业务

+   车队监控

+   物流捕捉

+   处理传感器

+   数据订单履行

+   任务排队

以下部分重点介绍了为低开销和使用经纪人的消息系统设计的部分。

## 低开销的消息系统

低开销的消息系统通常用于需要小占地面积或低延迟的环境。这些通常是传感器网络、嵌入式解决方案和物联网设备。它们在基于云的和分布式服务中较少见，但仍然可以在这些解决方案中使用。

### MQTT

**MQTT**代表**消息队列遥测传输**。它是 OASIS 和 ISO 下的开放标准。MQTT 通常使用 PubSub 模型，通常在 TCP/IP 上运行，但也可以与其他传输协议一起工作。

正如其名称所示，MQTT 的设计目标是低代码占用和在低带宽位置运行的可能性。还有一个名为**MQTT-SN**的单独规范，代表**传感器网络的 MQTT**。它专注于没有 TCP/IP 堆栈的电池供电的嵌入式设备。

MQTT 使用消息经纪人接收来自客户端的所有消息，并将这些消息路由到它们的目的地。QoS 提供了三个级别：

+   至多一次交付（无保证）

+   至少一次交付（已确认交付）

+   确保交付一次（已确认交付）

MQTT 特别受到各种物联网应用的欢迎并不奇怪。它受 OpenHAB、Node-RED、Pimatic、Microsoft Azure IoT Hub 和 Amazon IoT 的支持。它在即时通讯中也很受欢迎，在 ejabberd 和 Facebook Messanger 中使用。其他用例包括共享汽车平台、物流和运输。

支持此标准的两个最流行的 C++库是 Eclipse Paho 和基于 C++14 和 Boost.Asio 的 mqtt_cpp。对于 Qt 应用程序，还有 qmqtt。

### ZeroMQ

ZeroMQ 是一种无经纪人的消息队列。它支持常见的消息模式，如 PubSub、客户端/服务器和其他几种。它独立于特定的传输，并可以与 TCP、WebSockets 或 IPC 一起使用。

ZeroMQ 的主要思想是，它需要零经纪人和零管理。它也被宣传为提供零延迟，这意味着来自经纪人存在的延迟为零。

低级库是用 C 编写的，并且有各种流行编程语言的实现，包括 C++。C++的最受欢迎的实现是 cppzmq，这是一个针对 C++11 的仅头文件库。

## 经纪人消息系统

两个最受欢迎的不专注于低开销的消息系统是基于 AMQP 的 RabbitMQ 和 Apache Kafka。它们都是成熟的解决方案，在许多不同的设计中都非常受欢迎。许多文章都集中在 RabbitMQ 或 Apache Kafka 在特定领域的优越性上。

这是一个略微不正确的观点，因为这两种消息系统基于不同的范例。Apache Kafka 专注于流式传输大量数据并将流式存储在持久内存中，以允许将来重播。另一方面，RabbitMQ 通常用作不同微服务之间的消息经纪人或用于处理后台作业的任务队列。因此，在 RabbitMQ 中的路由比 Apache Kafka 中的路由更先进。Kafka 的主要用例是数据分析和实时处理。

虽然 RabbitMQ 使用 AMQP 协议（并且还支持其他协议，如 MQTT 和 STOMP），Kafka 使用基于 TCP/IP 的自己的协议。这意味着 RabbitMQ 与基于这些支持的协议的其他现有解决方案是可互操作的。如果您编写一个使用 AMQP 与 RabbitMQ 交互的应用程序，应该可以将其稍后迁移到使用 Apache Qpid、Apache ActiveMQ 或来自 AWS 或 Microsoft Azure 的托管解决方案。

扩展问题也可能会驱使选择一个消息代理而不是另一个。Apache Kafka 的架构允许轻松进行水平扩展，这意味着向现有工作机群添加更多机器。另一方面，RabbitMQ 的设计考虑了垂直扩展，这意味着向现有机器添加更多资源，而不是添加更多相似大小的机器。

# 使用 Web 服务

正如本章前面提到的，Web 服务的共同特点是它们基于标准的 Web 技术。大多数情况下，这将意味着**超文本传输协议**（**HTTP**），这是我们将重点关注的技术。尽管可能实现基于不同协议的 Web 服务，但这类服务非常罕见，因此超出了我们的范围。

## 用于调试 Web 服务的工具

使用 HTTP 作为传输的一个主要好处是工具的广泛可用性。在大多数情况下，测试和调试 Web 服务可以使用的工具不仅仅是 Web 浏览器。除此之外，还有许多其他程序可能有助于自动化。这些包括以下内容：

+   标准的 Unix 文件下载器`wget`

+   现代 HTTP 客户端`curl`

+   流行的开源库，如 libcurl、curlpp、C++ REST SDK、cpr（C++ HTTP 请求库）和 NFHTTP

+   测试框架，如 Selenium 或 Robot Framework

+   浏览器扩展，如 Boomerang

+   独立解决方案，如 Postman 和 Postwoman

+   专用测试软件，包括 SoapUI 和 Katalon Studio

基于 HTTP 的 Web 服务通过返回 HTTP 响应来处理使用适当的 HTTP 动词（如 GET、POST 和 PUT）的 HTTP 请求。请求和响应的语义以及它们应传达的数据在不同的实现中有所不同。

大多数实现属于两类：基于 XML 的 Web 服务和基于 JSON 的 Web 服务。基于 JSON 的 Web 服务目前正在取代基于 XML 的 Web 服务，但仍然常见到使用 XML 格式的服务。

对于处理使用 JSON 或 XML 编码的数据，可能需要额外的工具，如 xmllint、xmlstarlet、jq 和 libxml2。

## 基于 XML 的 Web 服务

最初获得关注的第一个 Web 服务主要基于 XML。**XML**或**可扩展标记语言**当时是分布式计算和 Web 环境中的交换格式选择。有几种不同的方法来设计带有 XML 有效负载的服务。

您可能希望与已经存在的基于 XML 的 Web 服务进行交互，这些服务可能是在您的组织内部开发的，也可能是外部开发的。但是，我们建议您使用更轻量级的方法来实现新的 Web 服务，例如基于 JSON 的 Web 服务、RESTful Web 服务或 gRPC。

### XML-RPC

最早出现的标准之一被称为 XML-RPC。该项目的理念是提供一种与当时盛行的**公共对象模型**（**COM**）和 CORBA 竞争的 RPC 技术。其目标是使用 HTTP 作为传输协议，并使格式既可读又可写，并且可解析为机器。为了实现这一点，选择了 XML 作为数据编码格式。

在使用 XML-RPC 时，想要执行远程过程调用的客户端向服务器发送 HTTP 请求。请求可能有多个参数。服务器以单个响应回答。XML-RPC 协议为参数和结果定义了几种数据类型。

尽管 SOAP 具有类似的数据类型，但它使用 XML 模式定义，这使得消息比 XML-RPC 中的消息不可读得多。

#### 与 SOAP 的关系

由于 XML-RPC 不再得到积极维护，因此没有现代的 C++实现标准。如果您想从现代代码与 XML-RPC Web 服务进行交互，最好的方法可能是使用支持 XML-RPC 和其他 XML Web 服务标准的 gSOAP 工具包。

XML-RPC 的主要批评是它在使消息显着变大的同时，没有比发送纯 XML 请求和响应提供更多价值。

随着标准的发展，它成为了 SOAP。作为 SOAP，它构成了 W3C Web 服务协议栈的基础。

### SOAP

**SOAP**的原始缩写是**Simple Object Access Protocol**。该缩写在标准的 1.2 版本中被取消。它是 XML-RPC 标准的演变。

SOAP 由三部分组成：

+   **SOAP 信封**，定义消息的结构和处理规则

+   **SOAP 头**规定应用程序特定数据类型的规则（可选）

+   **SOAP 主体**，携带远程过程调用和响应

这是一个使用 HTTP 作为传输的 SOAP 消息示例：

```cpp
POST /FindMerchants HTTP/1.1
Host: www.domifair.org
Content-Type: application/soap+xml; charset=utf-8
Content-Length: 345
SOAPAction: "http://www.w3.org/2003/05/soap-envelope"

<?xml version="1.0"?>
<soap:Envelope >
 <soap:Header>
 </soap:Header>
 <soap:Body >
    <m:FindMerchants>
      <m:Lat>54.350989</m:Lat>
      <m:Long>18.6548168</m:Long>
      <m:Distance>200</m:Distance>
    </m:FindMerchants>
  </soap:Body>
</soap:Envelope>
```

该示例使用标准的 HTTP 头和 POST 方法来调用远程过程。SOAP 特有的一个头是`SOAPAction`。它指向标识操作意图的 URI。由客户端决定如何解释此 URI。

`soap:Header`是可选的，所以我们将其留空。与`soap:Body`一起，它包含在`soap:Envelope`中。主要的过程调用发生在`soap:Body`中。我们引入了一个特定于多米尼加展会应用程序的 XML 命名空间。该命名空间指向我们域的根。我们调用的过程是`FindMerchants`，并提供三个参数：纬度、经度和距离。

由于 SOAP 被设计为可扩展、传输中立和独立于编程模型，它也导致了其他相关标准的产生。这意味着通常需要在使用 SOAP 之前学习所有相关的标准和协议。

如果您的应用程序广泛使用 XML，并且您的开发团队熟悉所有术语和规范，那么这不是问题。但是，如果您只是想为第三方公开 API，一个更简单的方法是构建 REST API，因为它对生产者和消费者来说更容易学习。

#### WSDL

**Web 服务描述语言**（**WSDL**）提供了服务如何被调用以及消息应该如何形成的机器可读描述。与其他 W3C Web 服务标准一样，它以 XML 编码。

它通常与 SOAP 一起使用，以定义 Web 服务提供的接口及其使用方式。

一旦在 WSDL 中定义了 API，您可以（而且应该！）使用自动化工具来帮助您从中创建代码。对于 C++，具有此类工具的一个框架是 gSOAP。它配备了一个名为`wsdl2h`的工具，它将根据定义生成一个头文件。然后您可以使用另一个工具`soapcpp2`，将接口定义生成到您的实现中。

不幸的是，由于消息的冗长，SOAP 服务的大小和带宽要求通常非常巨大。如果这不是问题，那么 SOAP 可以有其用途。它允许同步和异步调用，以及有状态和无状态操作。如果您需要严格、正式的通信手段，SOAP 可以提供。只需确保使用协议的 1.2 版本，因为它引入了许多改进。其中之一是服务的增强安全性。另一个是服务本身的改进定义，有助于互操作性，或者正式定义传输手段（允许使用消息队列）等，仅举几例。

#### UDDI

在记录 Web 服务接口之后的下一步是服务发现，它允许应用程序找到并连接到其他方实现的服务。

**通用描述、发现和集成**（**UDDI**）是用于 WSDL 文件的注册表，可以手动或自动搜索。与本节讨论的其他技术一样，UDDI 使用 XML 格式。

UDDI 注册表可以通过 SOAP 消息查询自动服务发现。尽管 UDDI 提供了 WSDL 的逻辑扩展，但其在开放中的采用令人失望。仍然可能会发现公司内部使用 UDDI 系统。

#### SOAP 库

SOAP 最流行的两个库是**Apache Axis**和**gSOAP**。

Apache Axis 适用于实现 SOAP（包括 WSDL）和 REST Web 服务。值得注意的是，该库在过去十年中没有发布新版本。

gSOAP 是一个工具包，允许创建和与基于 XML 的 Web 服务进行交互，重点是 SOAP。它处理数据绑定、SOAP 和 WSDL 支持、JSON 和 RSS 解析、UDDI API 等其他相关的 Web 服务标准。尽管它不使用现代 C++特性，但它仍在积极维护。

## 基于 JSON 的 Web 服务

**JSON**代表**JavaScript 对象表示法**。与名称所暗示的相反，它不仅限于 JavaScript。它是与语言无关的。大多数编程语言都有 JSON 的解析器和序列化器。JSON 比 XML 更紧凑。

它的语法源自 JavaScript，因为它是基于 JavaScript 子集的。

JSON 支持的数据类型如下：

+   数字：确切的格式可能因实现而异；在 JavaScript 中默认为双精度浮点数。

+   字符串：Unicode 编码。

+   布尔值：使用`true`和`false`值。

+   数组：可能为空。

+   对象：具有键值对的映射。

+   `null`：表示空值。

在第九章中介绍的`Packer`配置，即*持续集成/持续部署*，是 JSON 文档的一个示例：

```cpp
{
  "variables": {
    "aws_access_key": "",
    "aws_secret_key": ""
  },
  "builders": [{
    "type": "amazon-ebs",
    "access_key": "{{user `aws_access_key`}}",
    "secret_key": "{{user `aws_secret_key`}}",
    "region": "eu-central-1",
    "source_ami": "ami-5900cc36",
    "instance_type": "t2.micro",
    "ssh_username": "admin",
    "ami_name": "Project's Base Image {{timestamp}}"
  }],
  "provisioners": [{
    "type": "ansible",
    "playbook_file": "./provision.yml",
    "user": "admin",
    "host_alias": "baseimage"
  }],
  "post-processors": [{
    "type": "manifest",
    "output": "manifest.json",
    "strip_path": true
  }]
}
```

使用 JSON 作为格式的标准之一是 JSON-RPC 协议。

### JSON-RPC

JSON-RPC 是一种基于 JSON 编码的远程过程调用协议，类似于 XML-RPC 和 SOAP。与其 XML 前身不同，它需要很少的开销。它也非常简单，同时保持了 XML-RPC 的人类可读性。

这是我们之前的示例在 SOAP 调用中使用 JSON-RPC 2.0 的样子：

```cpp
{
  "jsonrpc": "2.0",
  "method": "FindMerchants",
  "params": {
    "lat": "54.350989",
    "long": "18.6548168",
    "distance": 200
  },
  "id": 1
}
```

这个 JSON 文档仍然需要适当的 HTTP 标头，但即使有标头，它仍然比 XML 对应物要小得多。唯一存在的元数据是带有 JSON-RPC 版本和请求 ID 的文件。`method`和`params`字段几乎是不言自明的。SOAP 并非总是如此。

尽管该协议轻量级、易于实现和使用，但与 SOAP 和 REST Web 服务相比，它并没有得到广泛的采用。它发布得比 SOAP 晚得多，大约与 REST 服务开始流行的时间相同。虽然 REST 迅速取得成功（可能是因为其灵活性），但 JSON-RPC 未能获得类似的推动力。

C++的两个有用的实现是 libjson-rpc-cpp 和 json-rpc-cxx。json-rpc-cxx 是先前库的现代重新实现。

## 表述性状态转移（REST）

Web 服务的另一种替代方法是**表述性状态转移（REST）。**符合这种架构风格的服务通常被称为 RESTful 服务。REST 与 SOAP 或 JSON-RPC 的主要区别在于 REST 几乎完全基于 HTTP 和 URI 语义。

REST 是一种在实现 Web 服务时定义一组约束的架构风格。符合这种风格的服务称为 RESTful。这些约束如下：

+   必须使用客户端-服务器模型。

+   无状态性（客户端和服务器都不需要存储与它们的通信相关的状态）。

+   可缓存性（响应应定义为可缓存或不可缓存，以从标准 Web 缓存中获益，以提高可伸缩性和性能）。

+   分层系统（代理和负载均衡器绝对不能影响客户端和服务器之间的通信）。

REST 使用 HTTP 作为传输协议，URI 表示资源，HTTP 动词操作资源或调用操作。关于每个 HTTP 方法应如何行为没有标准，但最常同意的语义是以下内容：

+   POST - 创建新资源。

+   GET - 检索现有资源。

+   PATCH - 更新现有资源。

+   DELETE - 删除现有资源。

+   PUT - 替换现有资源。

由于依赖于 Web 标准，RESTful Web 服务可以重用现有组件，如代理、负载均衡器和缓存。由于开销低，这样的服务也非常高效和有效。

### 描述语言

就像基于 XML 的 Web 服务一样，RESTful 服务可以以机器和人可读的方式描述。有几种竞争标准可用，其中 OpenAPI 是最受欢迎的。

#### OpenAPI

OpenAPI 是由 Linux Foundation 的 OpenAPI 计划监督的规范。它以前被称为 Swagger 规范，因为它曾经是 Swagger 框架的一部分。

该规范与语言无关。它使用 JSON 或 YAML 输入来生成方法、参数和模型的文档。这样，使用 OpenAPI 有助于保持文档和源代码的最新状态。

有许多与 OpenAPI 兼容的工具可供选择，例如代码生成器、编辑器、用户界面和模拟服务器。OpenAPI 生成器可以使用 cpp-restsdk 或 Qt 5 生成 C++代码进行客户端实现。它还可以使用 Pistache、Restbed 或 Qt 5 QHTTPEngine 生成服务器代码。还有一个方便的在线 OpenAPI 编辑器可用：[`editor.swagger.io/`](https://editor.swagger.io/)。

使用 OpenAPI 记录的 API 将如下所示：

```cpp
{
  "openapi": "3.0.0",
  "info": {
    "title": "Items API overview",
    "version": "2.0.0"
  },
  "paths": {
    "/item/{itemId}": {
      "get": {
        "operationId": "getItem",
        "summary": "get item details",
        "parameters": [
          "name": "itemId",
          "description": "Item ID",
          "required": true,
          "schema": {
            "type": "string"
          }
        ],
        "responses": {
          "200": {
            "description": "200 response",
            "content": {
              "application/json": {
                "example": {
                  "itemId": 8,
                  "name", "Kürtőskalács",
                  "locationId": 5
                }
              }
            }
          }
        }
      }
    }
  }
}
```

前两个字段（`openapi`和`info`）是描述文档的元数据。`paths`字段包含与 REST 接口的资源和方法对应的所有可能路径。在上面的示例中，我们只记录了一个路径（`/item`）和一个方法（`GET`）。此方法将`itemId`作为必需参数。我们提供了一个可能的响应代码，即`200`。200 响应包含一个 JSON 文档作为其本身的主体。与`example`键相关联的值是成功响应的示例有效负载。

#### RAML

一种竞争规范，RAML，代表 RESTful API 建模语言。它使用 YAML 进行描述，并实现了发现、代码重用和模式共享。

建立 RAML 的理念是，虽然 OpenAPI 是一个很好的工具来记录现有的 API，但在当时，它并不是设计新 API 的最佳方式。目前，该规范正在考虑成为 OpenAPI 计划的一部分。

RAML 文档可以转换为 OpenAPI 以利用可用的工具。

以下是使用 RAML 记录的 API 的示例：

```cpp
#%RAML 1.0

title: Items API overview
version: 2.0.0

annotationTypes:
  oas-summary:
    type: string
    allowedTargets: Method

/item:
  get:
    displayName: getItem
    queryParameters:
      itemId:
        type: string
    responses:
      '200':
        body:
          application/json:
            example: |
              {
                "itemId": 8,
                "name", "Kürtőskalács",
                "locationId": 5
              }
        description: 200 response
    (oas-summary): get item details
```

此示例描述了先前使用 OpenAPI 记录的相同接口。当以 YAML 序列化时，OpenAPI 3.0 和 RAML 2.0 看起来非常相似。主要区别在于，OpenAPI 3.0 要求使用 JSON 模式来记录结构。使用 RAML 2.0，可以重用现有的 XML 模式定义（XSD），这样更容易从基于 XML 的 Web 服务迁移或包含外部资源。

#### API Blueprint

API Blueprint 提出了与前两个规范不同的方法。它不依赖于 JSON 或 YAML，而是使用 Markdown 来记录数据结构和端点。

其方法类似于测试驱动的开发方法论，因为它鼓励在实施功能之前设计合同。这样，更容易测试实现是否真正履行了合同。

就像 RAML 一样，可以将 API Blueprint 规范转换为 OpenAPI，反之亦然。还有一个命令行界面和一个用于解析 API Blueprint 的 C++库，名为 Drafter，您可以在您的代码中使用。

使用 API Blueprint 记录的简单 API 示例如下：

```cpp
FORMAT: 1A

# Items API overview

# /item/{itemId}

## GET

+ Response 200 (application/json)

        {
            "itemId": 8,
            "name": "Kürtőskalács",
            "locationId": 5
        }
```

在上文中，我们看到针对`/item`端点的`GET`方法应该产生一个`200`的响应代码。在下面是我们的服务通常会返回的 JSON 消息。

API Blueprint 允许更自然的文档编写。主要缺点是它是迄今为止描述的格式中最不受欢迎的。这意味着文档和工具都远远不及 OpenAPI 的质量。

#### RSDL

类似于 WSDL，**RSDL**（或**RESTful Service Description Language**）是用于 Web 服务的 XML 描述。它与语言无关，旨在既适合人类阅读又适合机器阅读。

它比之前介绍的替代方案要不受欢迎得多。而且，它也要难得多，特别是与 API Blueprint 或 RAML 相比。

### 超媒体作为应用状态的引擎

尽管提供诸如基于*gRPC*的二进制接口可以提供出色的性能，但在许多情况下，您仍然希望拥有 RESTful 接口的简单性。如果您想要一个直观的基于 REST 的 API，**超媒体作为应用状态的引擎**（**HATEOAS**）可能是一个有用的原则。

就像您打开网页并根据显示的超媒体导航一样，您可以使用 HATEOAS 编写您的服务来实现相同的功能。这促进了服务器和客户端代码的解耦，并允许客户端快速了解哪些请求是有效的，这通常不适用于二进制 API。发现是动态的，并且基于提供的超媒体。

如果您使用典型的 RESTful 服务，在执行操作时，您会得到包含对象状态等数据的 JSON。除此之外，除此之外，您还会得到一个显示您可以在该对象上运行的有效操作的链接（URL）列表。这些链接（超媒体）是应用的引擎。换句话说，可用的操作由资源的状态确定。虽然在这种情况下，超媒体这个术语可能听起来很奇怪，但它基本上意味着链接到资源，包括文本、图像和视频。

例如，如果我们有一个 REST 方法允许我们使用 PUT 方法添加一个项目，我们可以添加一个返回参数，该参数链接到以这种方式创建的资源。如果我们使用 JSON 进行序列化，这可能采用以下形式：

```cpp
{
    "itemId": 8,
    "name": "Kürtőskalács",
    "locationId": 5,
    "links": [
        {
            "href": "item/8",
            "rel": "items",
            "type" : "GET"
        }
    ]
}
```

没有普遍接受的 HATEOAS 超媒体序列化方法。一方面，这样做可以更容易地实现，而不受服务器实现的影响。另一方面，客户端需要知道如何解析响应以找到相关的遍历数据。

HATEOAS 的好处之一是，它使得可以在服务器端实现 API 更改，而不一定会破坏客户端代码。当一个端点被重命名时，新的端点会在随后的响应中被引用，因此客户端会被告知在哪里发送进一步的请求。

相同的机制可能提供诸如分页或者使得发现给定对象可用方法变得容易的功能。回到我们的项目示例，这是我们在进行`GET`请求后可能收到的一个可能的响应：

```cpp
{
    "itemId": 8,
    "name": "Kürtőskalács",
    "locationId": 5,
    "stock": 8,
    "links": [
        {
            "href": "item/8",
            "rel": "items",
            "type" : "GET"
        },
        {
            "href": "item/8",
            "rel": "items",
            "type" : "POST"
        },
        {
            "href": "item/8/increaseStock",
            "rel": "increaseStock",
            "type" : "POST"
        }, 
        {
            "href": "item/8/decreaseStock",
            "rel": "decreaseStock",
            "type" : "POST"
        }
    ]
}
```

在这里，我们得到了两个负责修改库存的方法的链接。如果库存不再可用，我们的响应将如下所示（请注意，其中一个方法不再被广告）：

```cpp
{
    "itemId": 8,
    "name": "Kürtőskalács",
    "locationId": 5,
    "stock": 0,
    "links": [
        {
            "href": "items/8",
            "rel": "items",
            "type" : "GET"
        },
        {
            "href": "items/8",
            "rel": "items",
            "type" : "POST"
        },
        {
            "href": "items/8/increaseStock",
            "rel": "increaseStock",
            "type" : "POST"
        }
    ]
}
```

与 HATEOAS 相关的一个重要问题是，这两个设计原则似乎相互矛盾。如果遍历超媒体总是以相同的格式呈现，那么它将更容易消费。这里的表达自由使得编写不了解服务器实现的客户端变得更加困难。

并非所有的 RESTful API 都能从引入这一原则中受益-通过引入 HATEOAS，您承诺以特定方式编写客户端，以便它们能够从这种 API 风格中受益。

### C++中的 REST

Microsoft 的 C++ REST SDK 目前是在 C++应用程序中实现 RESTful API 的最佳方法之一。也被称为 cpp-restsdk，这是我们在本书中使用的库，用于说明各种示例。

## GraphQL

REST Web 服务的一个最新替代品是 GraphQL。名称中的**QL**代表**查询语言**。GraphQL 客户端直接查询和操作数据，而不是依赖服务器来序列化和呈现必要的数据。除了责任的逆转，GraphQL 还具有使数据处理更容易的机制。类型、静态验证、内省和模式都是规范的一部分。

有许多语言的 GraphQL 服务器实现，包括 C++。其中一种流行的实现是来自 Microsoft 的 cppgraphqlgen。还有许多工具可帮助开发和调试。有趣的是，由于 Hasura 或 PostGraphile 等产品在 Postgres 数据库上添加了 GraphQL API，您可以使用 GraphQL 直接查询数据库。

# 利用托管服务和云提供商

面向服务的架构可以延伸到当前的云计算趋势。虽然企业服务总线通常具有内部开发的服务，但使用云计算可以使用一个或多个云提供商提供的服务。

在为云计算设计应用程序架构时，您应该在实施任何替代方案之前始终考虑提供商提供的托管服务。例如，在决定是否要使用自己选择的插件托管自己的 PostgreSQL 数据库之前，确保您了解与提供商提供的托管数据库托管相比的权衡和成本。

当前的云计算环境提供了许多旨在处理流行用例的服务，例如以下内容：

+   存储

+   关系数据库

+   文档（NoSQL）数据库

+   内存缓存

+   电子邮件

+   消息队列

+   容器编排

+   计算机视觉

+   自然语言处理

+   文本转语音和语音转文本

+   监控、日志记录和跟踪

+   大数据

+   内容传送网络

+   数据分析

+   任务管理和调度

+   身份管理

+   密钥和秘钥管理

由于可用的第三方服务选择很多，很明显云计算如何适用于面向服务的架构。

## 云计算作为 SOA 的延伸

云计算是虚拟机托管的延伸。区别云计算提供商和传统 VPS 提供商的是两个东西：

+   云计算通过 API 可用，这使其成为一个服务本身。

+   除了虚拟机实例，云计算还提供额外的服务，如存储、托管数据库、可编程网络等。所有这些服务也都可以通过 API 获得。

有几种方式可以使用云提供商的 API 在您的应用程序中使用，我们将在下面介绍。

### 直接使用 API 调用

如果您的云提供商提供了您选择的语言可访问的 API，您可以直接从应用程序与云资源交互。

例如：您有一个允许用户上传自己图片的应用程序。该应用程序使用云 API 为每个新注册用户创建存储桶：

```cpp
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/CreateBucketRequest.h>

#include <spdlog/spdlog.h>

const Aws::S3::Model::BucketLocationConstraint region =
    Aws::S3::Model::BucketLocationConstraint::eu_central_1;

bool create_user_bucket(const std::string &username) {
  Aws::S3::Model::CreateBucketRequest request;

  Aws::String bucket_name("userbucket_" + username);
  request.SetBucket(bucket_name);

  Aws::S3::Model::CreateBucketConfiguration bucket_config;
  bucket_config.SetLocationConstraint(region);
  request.SetCreateBucketConfiguration(bucket_config);

  Aws::S3::S3Client s3_client;
  auto outcome = s3_client.CreateBucket(request);

  if (!outcome.IsSuccess()) {
    auto err = outcome.GetError();
    spdlog::error("ERROR: CreateBucket: {}: {}", 
                  err.GetExceptionName(),
                  err.GetMessage());
    return false;
  }

  return true;
}
```

在这个例子中，我们有一个 C++函数，它创建一个名为提供参数中的用户名的 AWS S3 存储桶。该存储桶配置为驻留在特定区域。如果操作失败，我们希望获取错误消息并使用`spdlog`记录。

### 通过 CLI 工具使用 API 调用

有些操作不必在应用程序运行时执行。它们通常在部署期间运行，因此可以在 shell 脚本中自动化。一个这样的用例是调用 CLI 工具来创建一个新的 VPC：

```cpp
gcloud compute networks create database --description "A VPC to access the database from private instances"
```

我们使用 Google Cloud Platform 的 gcloud CLI 工具创建一个名为`database`的网络，该网络将用于处理来自私有实例到数据库的流量。

### 使用与云 API 交互的第三方工具

让我们看一个例子，运行 HashiCorp Packer 来构建一个预先配置了你的应用程序的虚拟机实例镜像：

```cpp
{
   variables : {
     do_api_token : {{env `DIGITALOCEAN_ACCESS_TOKEN`}} ,
     region : fra1 ,
     packages : "customer"
     version : 1.0.3
  },
   builders : [
    {
       type : digitalocean ,
       api_token : {{user `do_api_token`}} ,
       image : ubuntu-20-04-x64 ,
       region : {{user `region`}} ,
       size : 512mb ,
       ssh_username : root
    }
  ],
  provisioners: [
    {
       type : file ,
       source : ./{{user `package`}}-{{user `version`}}.deb ,
       destination : /home/ubuntu/
    },
    {
       type : shell ,
       inline :[
         dpkg -i /home/ubuntu/{{user `package`}}-{{user `version`}}.deb
      ]
    }
  ]
}
```

在前面的代码中，我们提供了所需的凭据和区域，并使用构建器为我们准备了一个来自 Ubuntu 镜像的实例。我们感兴趣的实例需要有 512MB 的 RAM。然后，我们首先通过发送一个`.deb`包给它来提供实例，然后通过执行一个 shell 命令来安装这个包。

### 访问云 API

通过 API 访问云计算资源是区别于传统托管的最重要特性之一。使用 API 意味着你能够随意创建和删除实例，而无需操作员的干预。这样，就可以非常容易地实现基于负载的自动扩展、高级部署（金丝雀发布或蓝绿发布）以及应用程序的自动开发和测试环境。

云提供商通常将他们的 API 公开为 RESTful 服务。此外，他们通常还为几种编程语言提供客户端库。虽然三个最受欢迎的提供商都支持 C++作为客户端库，但来自较小供应商的支持可能有所不同。

如果你考虑将你的 C++应用程序部署到云上，并计划使用云 API，请确保你的提供商已发布了 C++ **软件开发工具包**（**SDK**）。也可以在没有官方 SDK 的情况下使用云 API，例如使用 CPP REST SDK 库，但请记住，这将需要更多的工作来实现。

要访问**Cloud SDK**，你还需要访问控制。通常，你的应用程序可以通过两种方式进行云 API 的身份验证：

+   **通过提供 API 令牌**

API 令牌应该是秘密的，永远不要存储在版本控制系统的一部分或编译后的二进制文件中。为了防止被盗，它也应该在静态时加密。

将 API 令牌安全地传递给应用程序的一种方法是通过像 HashiCorp Vault 这样的安全框架。它是可编程的秘密存储，内置租赁时间管理和密钥轮换。

+   **通过托管在具有适当访问权限的实例上**

许多云提供商允许给予特定虚拟机实例访问权限。这样，托管在这样一个实例上的应用程序就不必使用单独的令牌进行身份验证。访问控制是基于云 API 请求的实例。

这种方法更容易实现，因为它不必考虑秘密管理的需求。缺点是，当实例被入侵时，访问权限将对所有在那里运行的应用程序可用，而不仅仅是你部署的应用程序。

### 使用云 CLI

云 CLI 通常由人类操作员用于与云 API 交互。或者，它可以用于脚本编写或使用官方不支持的语言与云 API 交互。

例如，以下 Bourne Shell 脚本在 Microsoft Azure 云中创建一个资源组，然后创建属于该资源组的虚拟机：

```cpp
#!/bin/sh
RESOURCE_GROUP=dominicanfair
VM_NAME=dominic
REGION=germanynorth

az group create --name $RESOURCE_GROUP --location $REGION

az vm create --resource-group $RESOURCE_GROUP --name $VM_NAME --image UbuntuLTS --ssh-key-values dominic_key.pub
```

当寻找如何管理云资源的文档时，你会遇到很多使用云 CLI 的例子。即使你通常不使用 CLI，而更喜欢像 Terraform 这样的解决方案，有云 CLI 在手可能会帮助你调试基础设施问题。

### 使用与云 API 交互的工具

您已经了解了在使用云提供商的产品时出现供应商锁定的危险。通常，每个云提供商都会为所有其他提供商提供不同的 API 和不同的 CLI。也有一些较小的提供商提供抽象层，允许通过类似于知名提供商的 API 访问其产品。这种方法旨在帮助将应用程序从一个平台迁移到另一个平台。

尽管这样的情况很少见，但通常用于与一个提供商的服务进行交互的工具与另一个提供商的工具不兼容。当您考虑从一个平台迁移到另一个平台时，这不仅是一个问题。如果您想在多个提供商上托管应用程序，这也可能会成为一个问题。

为此，有一套新的工具，统称为**基础设施即代码**（**IaC**）工具，它们在不同提供商的顶部提供了一个抽象层。这些工具不一定仅限于云提供商。它们通常是通用的，并有助于自动化应用程序架构的许多不同层。

在[第九章](https://cdp.packtpub.com/hands_on_software_architecture_with_c__/wp-admin/post.php?post=33&action=edit)，*持续集成和持续部署*，我们简要介绍了其中一些。

## 云原生架构

新工具使架构师和开发人员能够更加抽象地构建基础架构，首先并且主要是考虑云。流行的解决方案，如 Kubernetes 和 OpenShift，正在推动这一趋势，但该领域还包括许多较小的参与者。本书的最后一章专门讨论了云原生设计，并描述了这种构建应用程序的现代方法。

# 总结

在本章中，我们了解了实施面向服务的体系结构的不同方法。由于服务可能以不同的方式与其环境交互，因此有许多可供选择的架构模式。我们了解了最流行的架构模式的优缺点。

我们专注于一些广受欢迎的方法的架构和实施方面：消息队列，包括 REST 的 Web 服务，以及使用托管服务和云平台。我们将在独立章节中更深入地介绍其他方法，例如微服务和容器。

在下一章中，我们将研究微服务。

# 问题

1.  面向服务的体系结构中服务的属性是什么？

1.  Web 服务的一些好处是什么？

1.  何时微服务不是一个好选择？

1.  消息队列的一些用例是什么？

1.  选择 JSON 而不是 XML 有哪些好处？

1.  REST 如何建立在 Web 标准之上？

1.  云平台与传统托管有何不同？

# 进一步阅读

+   *SOA 简化*：[`www.packtpub.com/product/soa-made-simple/9781849684163`](https://www.packtpub.com/product/soa-made-simple/9781849684163)

+   *SOA 食谱*：[`www.packtpub.com/product/soa-cookbook/9781847195487`](https://www.packtpub.com/product/soa-cookbook/9781847195487)
