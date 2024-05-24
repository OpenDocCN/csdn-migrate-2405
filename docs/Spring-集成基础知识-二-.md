# Spring 集成基础知识（二）

> 原文：[`zh.annas-archive.org/md5/9D4CBB216DD76C0D911041CB2D6145BA`](https://zh.annas-archive.org/md5/9D4CBB216DD76C0D911041CB2D6145BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：与 Spring Batch 的集成

如今，常见的用户会处理网络应用、移动应用和桌面软件。所有这些都是交互式的，这意味着它们需要用户输入并实时做出响应。他们可能甚至不知道其他类型的应用——后台运行、不需要持续用户交互，并且可能持续数小时、数天甚至数周的应用！是的，我在谈论通常用于离线处理如文件类型转换、报告、数据挖掘等任务的批量作业。在早期，机器太慢了，有人必须坐上几小时才能完成一个简单的任务。在批量处理中，你提交任务然后去做其他工作——你只来收集结果！这一革命改变了计算世界，证明了设备和程序员高昂价格的合理性。毫不夸张地说，批量作业展示了计算机的真正力量和实用性。

如果批量作业这么重要，很明显 Spring 会提供很好的支持。Spring Batch 是提供批量处理全面支持的模块。在本章中，我们将探讨 Spring Integration 如何与 Spring Batch 模块集成。与 Spring 的模块化哲学同步，每个模块独立工作，同时提供必要的接口以便于与其他家族成员轻松集成。Spring Integration 可以通过消息与 Spring Batch 模块交互，并提供一个事件驱动机制来触发批量作业。本章将涵盖两个方面：

+   Spring Batch 简介

+   Spring Integration 和 Spring Batch

# Spring Batch

对于普通人来说，批量作业可以被定义为任何可以离线运行的任务。通常，它将是一个手动触发，在预期的完成时间之后可以收集结果。如果一切顺利，那真的很酷，但让我们列出一些挑战：

+   如果用于批量作业的外部系统（比如说托管文件的 FTP 服务器）失败了会怎样？

+   如果出于某种原因运行批量作业的机器需要重新启动，批量作业也会重新开始吗？

+   如果需要一些显式参数（例如，可能不适合自动化的认证详情）该怎么办？

+   未完成任务会再次尝试还是放弃？

+   我们如何处理事务和回滚？

+   我们如何以固定间隔或事件驱动的方式触发和调度作业？

+   如果作业在线程中运行，谁来管理资源同步？

+   我们如何处理失败？批量作业能否触发一些警报或发送通知？

有很多事情需要考虑——想象一下如果每个都要程序员来实现会有多困难！不要担心；Spring Batch 在那里帮助你。有了 Spring Integration 的帮助，甚至最初的触发部分也可以编程——完全不需要人工交互。

首先，Spring Batch 不是一个像 Quartz、Tivoli 那样的调度框架——相反，它利用了这些框架。它是一个非常轻量级的框架，提供了可重用的组件来解决前面提到的多数问题，例如，事务支持、可恢复作业的数据库支持、日志记录、审计等等。让我们从配置步骤开始，然后我们可以逐步过渡到示例。

## 先决条件

在我们可以使用 Spring Batch 模块之前，我们需要添加命名空间支持和 Maven 依赖项：

+   **命名空间支持**：可以通过以下代码添加命名空间支持：

    ```java
    <beans 

      xsi:schemaLocation="http://www.springframework.org/schema/beans
      http://www.springframework.org/schema/beans/spring-beans.xsd
      http://www.springframework.org/schema/batch
      http://www.springframework.org/schema/batch/spring-batch.xsd
      http://www.springframework.org/schema/context
      http://www.springframework.org/schema/context/spring-context.xsd
      http://www.springframework.org/schema/integration
      http://www.springframework.org/schema/integration/spring-integration.xsd">
    ```

+   **Maven 入口**：可以通过以下代码添加 Maven 入口支持：

    ```java
        <dependency>
          <groupId>org.springframework.batch</groupId>
          <artifactId>spring-batch-core</artifactId>
          <version>3.0.1.RELEASE</version>
        </dependency>

        <dependency>
          <groupId>postgresql</groupId>
          <artifactId>postgresql</artifactId>
          <version>9.0-801.jdbc4</version>
        </dependency>

        <dependency>
          <groupId>commons-dbcp</groupId>
          <artifactId>commons-dbcp</artifactId>
          <version>1.4</version>
        </dependency>
    ```

# 定义 Spring Batch 作业

在 Spring Batch 中，工作单元是一个*作业*，它封装了完成批量操作所需的其它所有方面。在我们深入了解如何配置和使用 Spring Batch 组件之前，让我们先熟悉一下 Spring Batch 作业中使用的基本术语。

## Spring Batch 作业语言

让我们先熟悉一下 Spring Batch 的基本领域语言，这将帮助我们理解示例：

+   `Job`：这代表一个批量处理，它有一个一对一的映射。对于每个批量处理，将有一个作业。它可以在 XML 或 Java 配置中定义——我使用了 XML 方法。

+   `Step`：这是作业的逻辑分解——一个作业有一个或多个步骤。它封装了作业的阶段。步骤是运行和控制批量作业的实际细节的逻辑单元。每个作业步骤可以指定其容错性——例如，在错误时跳过一项，停止作业等。

+   `JobInstance`：这是一个作业实例。例如，一个作业必须每天运行一次，每次运行都会由一个`JobInstance`来表示。

+   `JobParameter`：这是完成`JobInstance`所必需的参数。

+   `JobExcecution`：当一个作业的`JobInstance`被触发时，它可能完成或失败。每个`JobInstance`的触发都被包装成`JobExecution`。所以，例如，如果设置了重试，并且由于失败，`JobInstance`被触发三次（由于失败）才完成，那么就有三个`JobExecution`实例。

+   `StepExecution`：与`JobExecution`类似，`StepExecution`是运行一个步骤的一次尝试的实例。如果一个步骤在*n*次重试后完成，将有*n*个`StepExecution`实例。

+   `ExecutionContext`：批量作业的一个重要方面是能够重新启动和重新调度失败作业；为此，需要存储足够的信息，以便可以将其重新触发，类似于操作系统级别的进程上下文。`ExecutionContext`用于解决此用例，它提供存储与上下文相关的属性键/值对的存储。

+   `JobRepository`：这是所有上述单元的持久性包装器。底层数据库提供者可以来自 Spring Batch 支持的各种数据库之一。

+   `JobLauncher`：这是一个用于启动作业的接口。

+   `ItemReader`：此接口用于步骤读取输入。如果输入集已用尽，`ItemReader`应通过返回 null 来指示此情况。

+   `ItemWriter`：这是步骤的输出接口——一次一个批次或数据块。

+   `ItemProcessor`：这是`ItemReader`和`ItemWriter`的中间状态。它提供了将一个项目应用于转换或业务逻辑的机会。

有了前面的介绍，我们可以更好地理解 Spring Batch 示例。那么我们从定义一个批处理作业开始：

```java
<batch:job id="importEmployeeRecords" 
  job-repository="jobRepository" 
  parent="simpleJob">
  <batch:step id="loadEmployeeRecords">
    <batch:tasklet>
      <batch:chunk 
        reader="itemReader" 
        writer="itemWriter" 
        commit-interval="5"/>
    </batch:tasklet>
  </batch:step>
  <!-- Listener for status of JOB -->
  <batch:listeners>
    <batch:listener 
      ref="notificationExecutionsListener"/>
  </batch:listeners>
</batch:job>
```

以下是前面配置中使用的标签的简要描述：

+   `batch:job`：这是启动批处理作业的父标签。`id`用于唯一标识此作业，例如，在`JobLauncher`内引用此作业。

+   `batch:step`：这是此作业的一个步骤。

+   `batch:tasklet`：这是执行步骤实际任务的实现，而步骤则负责维护状态、事件处理等。

+   `batch:chunk`：一个`tasklet`可以是一个简单的服务或一个非常复杂的任务，而一个`chunk`是可以通过`tasklet`进行处理的工作逻辑单位。

+   `batch:listeners`：这些用于传播事件。我们将在本章后面重新访问这个。

读者和写入者是什么？正如名称所示，读者读取数据块，而写入者将其写回。Spring 提供了读取 CSV 文件的标准化读者，但我们可以提供自己的实现。让我们看看这个例子中使用的读者和写入者。

## ItemReader

```java
FlatFileItemReader reader to read data from a flat file:
```

```java
<bean id="itemReader" 
  class="org.springframework.batch.item.file.FlatFileItemReader" 
  scope="step">
  <property name="resource" 
    value="file:///#{jobParameters['input.file.name']}"/>
  <property name="lineMapper">
    <bean class=
      "org.springframework.batch.item.file.mapping.DefaultLineMapper">
      <property name="lineTokenizer">
        <bean class=
          "org.springframework.batch.item.file.transform.DelimitedLineTokenizer">
          <property name="names" 
            value="name,designation,dept,address"/>
        </bean>
      </property>
      <property name="fieldSetMapper">
        <bean class=
          "com.cpandey.siexample.batch.EmployeeFieldSetMapper"/>
      </property>
    </bean>
  </property>
</bean>
```

前面代码片段中使用的组件在以下项目点中解释：

+   `itemReader`：这使用了 Spring 的默认平面文件读取器，其位置在`resource`属性中提到。名称将从传递给作业的`JobParameter`条目中检索。我们将看到在编写启动器时如何传递它。

+   `lineMapper`：这是 Spring 提供的默认实现，用于将 CSV 文件中的行映射到行。

+   `lineTokenizer`：如何解释行中的每个令牌非常重要。属性`names`的值决定了顺序。例如，在前面的示例中，它是`name,designation,dept,address`，这意味着如果样本文件有一个条目如下：

    ```java
    Chandan, SWEngineer, RnD, India
    Pandey, Tester, RnD, India
    ```

    然后，每个数据块将被解释为姓名、职位、部门和地址，分别。

+   `fieldSetMapper`：虽然有一些默认实现，但在大多数情况下，它是一个自定义类，用于定义 CSV 文件中的条目和领域模型之间的映射。以下是使用映射器的示例代码片段：

    ```java
    import org.springframework.batch.item.file.mapping.FieldSetMapper;
    import org.springframework.batch.item.file.transform.FieldSet;
    import org.springframework.validation.BindException;

    public class EmployeeFieldSetMapper implements FieldSetMapper<Employee> {

    @Override
    public Employee mapFieldSet(FieldSet fieldSet) throws BindException {
        Employee employee = new Employee();
        employee.setName(fieldSet.readString("name"));
        employee.setDesignation(fieldSet.readString("designation"));
        employee.setDept(fieldSet.readString("dept"));
        employee.setAddress(fieldSet.readString("address"));
        return employee;
      }
    }
    ```

## ItemWriter

写入器用于写入数据块。写入器几乎总是用户定义的。它可以被定义为在文件、数据库或 JMS 中写入，或到任何端点——这取决于我们的实现。在章节的最后，我们将讨论如何使用它甚至触发 Spring Integration 环境中的事件。让我们首先看看一个简单的写入器配置：

```java
<bean id="itemWriter" 
class="com.cpandey.siexample.batch.EmployeeRecordWriter"/>
```

以下代码片段是写入器类的实现：

```java
import java.util.List;
import org.springframework.batch.item.ItemWriter;
public class EmployeeRecordWriter implements ItemWriter<Employee> {
  @Override
  public void write(List<? extends Employee> employees) throws
  Exception {
    if(employees!=null){
      for (Employee employee : employees) { 
        System.out.println(employee.toString());
      }
    }
  }
}
```

为了简单起见，我打印了记录，但如前所述，它可以在数据库中填充，或者可以用来在这个类中做我们想做的事情。

好吧，到目前为止，我们已经定义了作业、读取器和写入器；那么是什么阻止我们启动它呢？我们如何启动这个批处理作业？Spring 提供了`Joblauncher`接口，可以用来启动作业。`Joblauncher`需要一个`JobRepository`接口的实现来存储作业的上下文，以便在失败时可以恢复和重新启动。`JobRepository`可以配置为利用 Spring 可以使用的任何数据库，例如，内存、MySql、PostGres 等。让我们如下定义`jobLauncher`：

```java
<bean id="jobLauncher" 
  class="org.springframework.batch.core.launch.support.SimpleJobLauncher">
  <property name="jobRepository" ref="jobRepository"/>
</bean>
```

由于`JobLauncher`不能在没有`JobRepository`的情况下使用，让我们配置`JobRepository`：

```java
<bean id="jobRepository" 
  class="org.springframework.batch.core.repository.support.MapJobRepositoryFactoryBean">
  <property name="transactionManager" ref="transactionManager"/>
</bean>
```

```java
the configuration of a data source (this is an Apache DBCP implementation):
```

```java
import org.apache.commons.dbcp.BasicDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
@Configuration
public class BatchJdbcConfiguration {
  @Value("${db.driverClassName}")
  private String driverClassName;
  @Value("${db.url}")
  private String url;
  @Value("${db.username}")
  private String username;
  @Value("${db.password}")
  private String password;
  @Bean(destroyMethod = "close")

  public BasicDataSource dataSource() {
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setDriverClassName(driverClassName);
    dataSource.setUrl(url);
    dataSource.setUsername(username);
    dataSource.setPassword(password);
    return dataSource;
  }
}
```

前面代码中显示的属性可以在一个`properties`文件中配置，比如说`batch.properties`。我们可以将属性提供在类路径中，并使用`property-placeholder`标签来注入属性，如下所示：

```java
<context:property-placeholder 
  location="/META-INF/spring/integration/batch.properties"/> 
  db.password=root 
  db.username=postgres 
  db.databaseName=postgres 
  db.driverClassName=org.postgresql.Driver 
  db.serverName=localhost:5432 
  db.url=jdbc:postgresql://${db.serverName}/${db.databaseName}
```

一旦有了数据库，我们就需要事务！让我们配置事务管理器：

```java
<bean id="transactionManager" 
  class="org.springframework.batch.support.transaction. 
  ResourcelessTransactionManager" />
```

谢天谢地，不再有配置了！顺便说一下，这些不是针对任何批处理作业的；任何在现有应用程序中配置的数据源和事务管理器都可以使用。有了所有的配置，我们准备启动批处理作业。让我们看看以下示例代码：

```java
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.JobParametersInvalidException;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.batch.core.repository.JobExecutionAlreadyRunningException;
import org.springframework.batch.core.repository.JobInstanceAlreadyCompleteException;
import org.springframework.batch.core.repository.JobRestartException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class BatchJobLauncher {
  public static void main(String[] args) throws JobExecutionAlreadyRunningException, JobRestartException, JobInstanceAlreadyCompleteException, JobParametersInvalidException {
    ApplicationContext context = new ClassPathXmlApplicationContext("/META-INF/spring/integration/spring-integration-batch.xml");
    Job job = context.getBean("importEmployeeRecords", Job.class);
    JobLauncher jobLauncher= context.getBean("jobLauncher", JobLauncher.class);
    JobParametersBuilder jobParametersBuilder = new JobParametersBuilder();
    jobParametersBuilder.addString("input.file.name", "C:/workspace_sts/siexample/src/main/resources/META-INF/spring/integration/employee.input");
    JobExecution execution =jobLauncher.run(job, jobParametersBuilder.toJobParameters());
  }
}
```

让我们理解一下代码：

+   **加载文件**：我们首先加载配置文件。

+   **提取引用**：下一步是使用其唯一 ID 检索定义工作的引用。

+   **添加参数**：作业需要一个参数，因此我们使用`JobParameterBuilder`类定义`JobParameter`。传递给键值的文件名是`input.file.name`，这在作业定义中配置。

+   **启动作业**：最后，使用 Spring 的`JobLauncher`类来启动作业。

嗯！现在我们有一个小而简单的批处理程序正在运行。让我们看看 Spring Integration 如何利用其力量并进一步增强使用。

# Spring Batch 和 Spring Integration

通常，批处理应用程序可以通过命令行界面或程序化方式触发，例如，从一个 web 容器中。让我们引入 Spring Integration 并看看可能性：

+   它可以由事件触发，例如，文件适配器监听文件触发 Spring Integration 在文件到达时。

+   执行可以在流程中链接——触发作业，传递结果，调用错误路径等。

+   消息队列并不适合大量数据。因此，对于大文件，Spring Integration 可以充当触发器，同时将实际任务委托给 Spring Batch。它可以提供一种分块文件并将其分布到 Spring Batch 作业中的策略。

+   Spring Integration 不仅可以触发批处理作业，还可以收集结果并在系统中传播。例如，由 Spring Integration 触发的批处理过程可能在一天后结束，之后`ItemWriter`可以将一个条目写入 JMS，Spring Integration 适配器正在监听该 JMS。即使没有任何对启动作业的意识或锁定，队列中的消息也将由 Spring Integration 处理。

## 启动作业

够了理论！让我们写一些代码。这次，我们将在某些事件上触发批处理作业，而不是手动触发。我们正在处理一个文件，如果我们处理一个文件适配器会怎样？让我们写一个文件适配器，它将监听目录中的文件，并在文件可用时触发一个批处理作业：

```java
<int-file:inbound-channel-adapter id="fileAdapter" 
  directory="C:\Chandan\Projects\inputfolderforsi" 
  channel="filesOutputChannel" 
  prevent-duplicates="true" filename-pattern="*.txt"> 
  <int:poller fixed-rate="1000" />
</int-file:inbound-channel-adapter>
```

不需要定义文件适配器标签，因为它们在前一章中已经处理了。

前面的配置将监听配置目录中的文件。文件将被放入`fileOutPutChannel`作为`Message<File>`，我们需要将其转换为`JobLauncher`可以理解的形式。我们将使用`transformer`组件：

```java
<int:transformer 
  input-channel="filesOutputChannel" 
  output-channel="batchRequest">
  <bean class="com.cpandey.siexample.batch.FileMessageToJobRequest">
    <property name="job" ref="importEmployeeRecords"/>
    <property name="fileParameterName" value="input.file.name"/>
  </bean>
</int:transformer>
```

我们将不得不编写逻辑将`Message<File>`转换为`JobLaunchRequest`。以下代码是一个非常简单的转换器，它从`Message`的负载（即`File`）中提取文件路径，然后将检索到的路径作为`JobParameter`添加。这个作业参数然后用于使用 Spring 的`JobLauncher`启动作业，如下面的代码片段所示：

```java
import java.io.File;

import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.integration.launch.JobLaunchRequest;
import org.springframework.integration.annotation.Transformer;
import org.springframework.messaging.Message;

public class FileMessageToJobRequest {
  private Job job;
  private String fileParameterName;

  public void setFileParameterName(String fileParameterName) {
    this.fileParameterName = fileParameterName;
  }

  public void setJob(Job job) {
    this.job = job;
  }

  @Transformer
  public JobLaunchRequest toRequest(Message<File> message) {
  JobParametersBuilder jobParametersBuilder = new JobParametersBuilder();

  jobParametersBuilder.addString(fileParameterName,message.getPayload().getAbsolutePath());
  return new JobLaunchRequest(job,jobParametersBuilder.toJobParameters());
  }
}
```

有了这段代码，每当有新文件到达目录时，就会使用 Spring Integration 触发一个批处理作业。而且，文件适配器只是一个例子，任何适配器或网关——比如邮件、JMS、FTP 等——都可以插入以触发批处理。

## 跟踪批处理作业的状态

大多数时候，我们希望能够得到进行中的任务的反馈——我们怎样才能做到这一点呢？Spring Integration 是一个基于事件的事件框架，所以毫不奇怪，我们可以为批处理作业配置监听器。如果你参考开头的批处理作业定义，它有一个监听器定义：

```java
  <batch:listeners>
    <batch:listener ref="simpleListener"/>
  </batch:listeners>
```

这段代码可以有一个 Spring Integration 网关作为监听器，它监听通知并将批处理作业（类型为`JobExecution`）的状态放在定义的信道上：

```java
<int:gateway id=" simpleListener"
  service-interface="org.springframework.batch.core.JobExecutionListener" default-request-channel="jobExecutionsStatus"/>
```

状态将在我们完成处理的信道上可用。我们插入一个简单的服务激活器来打印状态：

```java
<int:service-activator
  ref="batchStatusServiceActivator"
  method="printStatus"
  input-channel="jobExecutionsStatus"/>

import org.springframework.batch.core.JobExecution;
import org.springframework.integration.annotation.MessageEndpoint;
import org.springframework.messaging.Message;

@MessageEndpoint
public class BatchStatusServiceActivator {
  public void printStatus(Message<JobExecution> status ) {
    if(status!=null){
      System.out.println("Status :: "+status.getPayload().toString());
    }
  }
}
```

## 反之亦然

Spring Integration 可以启动批处理作业，而 Spring Batch 可以与 Spring Integration 交互并触发组件。我们如何做到这一点呢？Spring Integration 的事件驱动组件是一个不错的选择。让我们来看一个简单的例子：

+   在 Spring Integration 应用程序中有一个入站 JMS 适配器，它监听队列上的消息，并基于此触发某些操作。

+   我们如何从 Spring Batch 中调用这个适配器呢？我们可以在 Spring Batch 中定义一个自定义的`ItemWriter`类，该类将其输出写入 JMS 队列，而 Spring Integration 组件正在监听该队列。

+   一旦`ItemWriter`将数据写入 JMS 队列，入站适配器就会将其捡起并传递给下一阶段进行进一步处理。

前面提到的用例只是其中之一；我们可以整合这两个框架的事件机制，实现所需的应用间通信。

# 总结

这就完成了我们关于 Spring Integration 和 Spring Batch 如何进行互联互通的讨论。我们介绍了 Spring Batch 的基础知识，如何被 Spring Integration 利用来委托处理大量负载，如何跟踪状态，以及随后 Spring Batch 如何触发事件并在 Spring Integration 应用程序中开始处理！

在下一章中，我们将讨论最重要的方面之一——测试。保持精力充沛！


# 第八章．测试支持

**测试驱动** **开发**（**TDD**）已经改变了软件的开发和部署方式，为什么不呢，每个客户都想要运行良好的软件——证明它运行良好最好的方式就是测试它！Spring Integration 也不例外——那么我们如何测试每个“单元”是否可以独立运行呢？——事实上，测试单元的重要性甚至更大，这样任何集成问题都可以很容易地被隔离。例如，FTP 入站网关依赖于外部因素，如 FTP 服务器上的用户角色、FTP 服务器的性能、网络延迟等。我们如何验证连接到 FTP 入站网关的消费者可以在不实际连接到 FTP 服务器的情况下处理文件？我们可以将“模拟”消息发送到通道，消费者会将其视为来自 FTP 服务器的消息！我们想要证明的就是，给定文件到达通道，监听器将执行其工作。

在本章中，我将涵盖 Spring Integration 测试的方面——而且大部分，它将是一个“给我看代码”的章节！以下是涵盖的主题的大纲：

+   测试消息

+   测试头部

+   处理错误

+   测试过滤器

+   测试分割器

# 先决条件

那么测试需要什么？当然，JUnit！还有别的吗？Spring 框架和 Spring Integration 本身提供了许多模拟和支持类，帮助测试应用程序。让我们为这些类添加 maven 依赖项：

```java
  <dependency>
    <groupId>org.springframework.integration</groupId>
    <artifactId>spring-integration-test</artifactId>
    <version>${spring.integration.version}</version>
  </dependency>
  <dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>${junit.version}</version>
  </dependency>
  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-test</artifactId>
    <version>${spring.version}</version>
    <scope>test</scope>
  </dependency>
```

# 测试消息

Spring Integration 提供了一个类，可以帮助构建某些有效负载，例如以下示例：

```java
Message<String> message = MessageBuilder.withPayload("Test").build()
```

这些消息可以通过获取实际通道定义的句柄放在通道上。这可以用于负测试以及正测试。例如，如果监听通道的服务激活器期望一个具有`File`类型的有效负载的消息，那么放置一个具有`String`有效负载的消息应该表示一个错误。让我们为我们的转换器编写一个快速的测试，该转换器接受具有`SyndEntry`有效负载的`Message`并将其转换为`SoFeed`。以下是我们转换器类的代码片段：

```java
import org.springframework.messaging.Message;

import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedDbTransformer {

  public SoFeed transformFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    SoFeed soFeed=new SoFeed();
    soFeed.setTitle(entry.getTitle());
    soFeed.setDescription(entry.getDescription().getValue());
    soFeed.setCategories(entry.getCategories());
    soFeed.setLink(entry.getLink());
    soFeed.setAuthor(entry.getAuthor());

    System.out.println("JDBC"+soFeed.getTitle());
    return soFeed;
  }
}
```

如提及的，它接收到一个具有`SyndEntry`类型的有效负载的消息。让我们编写一个简单的测试用例，只有在从`SyndEntry`成功转换到`SoFeed`时才会通过：

```java
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.springframework.integration.test.matcher.PayloadMatcher.hasPayload;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.integration.channel.QueueChannel;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndContent;
import com.sun.syndication.feed.synd.SyndContentImpl;
import com.sun.syndication.feed.synd.SyndEntry;
import com.sun.syndication.feed.synd.SyndEntryImpl;

@ContextConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
public class TestSoDBFeedTransformer {
  @Autowired
  MessageChannel filteredFeedChannel;

  @Autowired
  QueueChannel transformedChannel;

  @Test
  public void messageIsConvertedToEntity() {
    //Define a dummy domain Object
    SyndEntry entry =new SyndEntryImpl();
    entry.setTitle("Test");
    SyndContent content=new SyndContentImpl();
    content.setValue("TestValue");
    entry.setDescription(content);
    List<SyndCategoryImpl> catList=new 
      ArrayList<SyndCategoryImpl>();
    entry.setCategories(catList);
    entry.setLink("TestLink");
    entry.setAuthor("TestAuthor");

//Define expected result
    SoFeed expectedSoFeed=new SoFeed();
    expectedSoFeed.setTitle(entry.getTitle());
    expectedSoFeed.setDescription(entry.getDescription
      ().getValue());

      expectedSoFeed.setCategories(entry.getCategories()
      );
    expectedSoFeed.setLink(entry.getLink());
    expectedSoFeed.setAuthor(entry.getAuthor());

    Message<SyndEntry> message = 
      MessageBuilder.withPayload(entry).build();
    filteredFeedChannel.send(message);
    Message<?> outMessage = 
      transformedChannel.receive(0);
    SoFeedsoFeedReceived
      =(SoFeed)outMessage.getPayload();
    assertNotNull(outMessage);
    assertThat(outMessage, 
      hasPayload(soFeedReceived));
    outMessage = transformedChannel.receive(0);
    assertNull("Only one message expected", 
      outMessage);
  }
```

在此代码中，使用`@ContextConfiguration`注解加载上下文信息。默认情况下，它会寻找类似于`<classname>-context.xml`的文件名和用`@Configuration`注解的 Java 配置类。在我们的案例中，它是`TestSoDBFeedTransformer-context.xml`。这包含运行测试所需的信息，如通道、服务定义等：

```java
<?xml version="1.0" encoding="UTF-8"?>
  <beans 

      xsi:schemaLocation="http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
    http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <int:channel id="filteredFeedChannel"/>
    <int:channel id="transformedChannel">
      <int:queue/>
    </int:channel>

    <bean id="feedDbTransformerBean" 
      class="com.cpandey.siexample.transformer.SoFeedDbTransformer" />
    <!-- Transformers -->
    <int:transformer id="dbFeedTransformer" 
      ref="feedDbTransformerBean" 
      input-channel="filteredFeedChannel"
      method="transformFeed" 
      output-channel="transformedChannel"/>
  </beans>
```

本代码中涵盖的组件将在以下几点详细解释：

+   `@RunWith(SpringJUnit4ClassRunner.class)`：这定义了要在哪个引擎上运行测试——与 Spring Integration 无关。

+   `@Autowired MessageChannel filteredFeedChannel`：这自动注入了来自上下文文件的通道定义——无需显式加载即可使用。

+   `@Autowired QueueChannel transformedChannel`：这与前面一点相似，同时也自动注入了其他通道。

Spring 配置准备所有必需的元素——现在让我们看看测试类做什么：

1.  它创建了一个虚拟的`SyndEntry`。

1.  它根据那个`SyndEntry`创建了一个预期的`SoFeed`。

1.  它构建了一个载荷类型为`SyndEntry`的消息。

1.  它抓取了转换器插座的通道处理句柄并在其中放置了载荷。

    这是测试转换器的地方，调用的是监听通道的实际转换器实例（而不是模拟的）。

1.  转换器进行转换，并将结果放在输出通道上。

1.  测试类抓取了输出通道的处理句柄并读取了消息。

    输出通道上的实际转换消息必须与构造的预期消息匹配。

通过上述步骤，我们能够测试一个实际的转换器，而不必过多担心通道或其他与系统外部有关的 Spring Integration 元素。

# 测试头部

在测试载荷时，测试头部相对容易。我们来编写一个头部丰富器，然后一个测试用例来验证它：

```java
  <int:header-enricher 
    input-channel="filteredFeedChannel" output-channel="transformedChannel">
    <int:header name="testHeaderKey1" value="testHeaderValue1"/>
    <int:header name="testHeaderKey2" value="testHeaderValue2"/>
  </int:header-enricher>
```

任何放入`filteredFeedChannel`的消息都会添加头部。以下代码片段是验证这些头部是否被添加的测试用例：

```java
import static org.junit.Assert.assertThat;
import static org.springframework.integration.test.matcher.HeaderMatcher.hasHeader;
import static org.springframework.integration.test.matcher.HeaderMatcher.hasHeaderKey;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.integration.channel.QueueChannel;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration
// default context name is <ClassName>-context.xml
@RunWith(SpringJUnit4ClassRunner.class)
public class TestSoHeaderAddition {
  @Autowired
  MessageChannel filteredFeedChannel;

  @Autowired
  QueueChannel transformedChannel;

  @Test
  public void headerIsAddedToEntity() {
    Message<String> message = MessageBuilder.withPayload("testheader").build();
    filteredFeedChannel.send(message);
    Message<?> outMessage = transformedChannel.receive(0);
    assertThat(outMessage, hasHeaderKey("testHeaderKey1"));
    assertThat(outMessage, hasHeader("testHeaderKey1", "testHeaderValue1"));
  }
}
```

在这里，我们构建了一个测试消息并将其放入通道中。一个头部丰富器被插入了输入通道，它向载荷添加了一个头部。我们通过从输出通道提取消息来验证这一点。

# 处理错误

到目前为止还好，那么处理错误场景呢？如何测试负面用例以及失败的测试用例怎么办？以下代码片段将帮助我们处理这些问题：

```java
  @Test(expected = MessageTransformationException.class)
  public void errorReportedWhenPayloadIsWrong() {
    Message<String> message = 
      MessageBuilder.withPayload("this should fail").build();
    filteredFeedChannel.send(message);
  }
```

输入通道期望的是一个载荷类型为`SyndEntry`的消息，但如果发送了一个载荷类型为`String`的消息——这必须抛出异常。这就是已经测试过的。这可以进一步增强，以监控具有验证用户定义传播消息能力的通道上的某些类型的异常。

# 测试过滤器

我们已经定义了一个过滤器，它过滤掉所有除了 java feed 之外的消息。我们为什么要单独讨论过滤器呢？如果你记得，过滤器总是返回一个布尔值，根据它是否满足条件来指示是否传递消息或丢弃它。为了方便参考，以下是我们定义的过滤器的代码片段：

```java
import java.util.List;
import org.springframework.messaging.Message;
import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedFilter {
  public boolean filterFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    List<SyndCategoryImpl>
      categories=entry.getCategories();
    if(categories!=null&&categories.size()>0){
      for (SyndCategoryImpl category: categories) {

        if(category.getName().equalsIgnoreCase("java")){
          return true;
        }

      }
    }
    return false;
  }
}
```

让我们创建一个测试上下文类来测试这个。总是最好有一个单独的上下文类来测试，这样就不会弄乱实际的运行环境。

现在，我们编写测试用例——第一个用例是验证所有类型为`java`的消息都被允许通过：

```java
  @Test
  public void javaMessagePassedThrough() {
    SyndEntry entry =new SyndEntryImpl();
    entry.setTitle("Test");
    SyndContent content=new SyndContentImpl();
    content.setValue("TestValue");
    entry.setDescription(content);
    List<SyndCategoryImpl> catList=new 
      ArrayList<SyndCategoryImpl>();
    SyndCategoryImpl category=new SyndCategoryImpl();
    category.setName("java");
    catList.add(category);
    entry.setCategories(catList);
    entry.setLink("TestLink");
    entry.setAuthor("TestAuthor");

    Message<SyndEntry> message = 
      MessageBuilder.withPayload(entry).build();
    fetchedFeedChannel.send(message);
    Message<?> outMessage = filteredFeedChannel.receive(0);
    assertNotNull("Expected an output message", outMessage);
    assertThat(outMessage, hasPayload(entry));
  }
```

```java
is used to test whether any other message except the category java is dropped:
```

```java
  @Test
  public void nonJavaMessageDropped() {
    SyndEntry entry =new SyndEntryImpl();
    entry.setTitle("Test");
    SyndContent content=new SyndContentImpl();
    content.setValue("TestValue");
    entry.setDescription(content);
    List<SyndCategoryImpl> catList=new 
      ArrayList<SyndCategoryImpl>();
    SyndCategoryImpl category=new SyndCategoryImpl();
    category.setName("nonjava");
    catList.add(category);
    entry.setCategories(catList);
    entry.setLink("TestLink");
    entry.setAuthor("TestAuthor");

    Message<SyndEntry> message = 
      MessageBuilder.withPayload(entry).build();
    fetchedFeedChannel.send(message);
    Message<?> outMessage = filteredFeedChannel.receive(0);
    assertNull("Expected no output message", outMessage);
  }
```

# 分割器测试

让我们讨论一下最后一个测试——这是针对分割器的。我们所定义的分割器如下：

```java
import org.springframework.messaging.Message;

import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedSplitter {
  public List<SyndCategoryImpl> splitAndPublish(Message<SyndEntry> message) {
    SyndEntry syndEntry=message.getPayload();
    List<SyndCategoryImpl> categories= syndEntry.getCategories();
    return categories;
  }
}
```

以下代码片段代表我们的测试类：

```java
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.springframework.integration.test.matcher.HeaderMatcher.hasHeader;
import static org.springframework.integration.test.matcher.HeaderMatcher.hasHeaderKey;
import static org.springframework.integration.test.matcher.PayloadMatcher.hasPayload;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.integration.channel.QueueChannel;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndContent;
import com.sun.syndication.feed.synd.SyndContentImpl;
import com.sun.syndication.feed.synd.SyndEntry;
import com.sun.syndication.feed.synd.SyndEntryImpl;

@ContextConfiguration	// default context name is <ClassName>-context.xml
@RunWith(SpringJUnit4ClassRunner.class)
public class TestSplitter {
  //Autowire required channels
  @Autowired
  MessageChannel filteredFeedChannel;

  @Autowired
  QueueChannel splitFeedOutputChannel;

  @Test
  public void javaMessagePassedThrough() {
    //Create MOCK payload
    //Create a SyndEntry Object
    SyndEntry entry =new SyndEntryImpl();
    entry.setTitle("Test");
    //Create a SyndContent to be used with entry
    SyndContent content=new SyndContentImpl();
    content.setValue("TestValue");
    entry.setDescription(content);
    //Create List which is expected on Channel
    List<SyndCategoryImpl> catList=new ArrayList<SyndCategoryImpl>();
    //Create Categories
    SyndCategoryImpl category1=new SyndCategoryImpl();
    category1.setName("java");
    category1.setTaxonomyUri("");
    SyndCategoryImpl category2=new SyndCategoryImpl();
    category2.setName("java");
    category2.setTaxonomyUri("");
    //Add categories
    catList.add(category1);
    catList.add(category2);
    //Complete entry
    entry.setCategories(catList);
    entry.setLink("TestLink");
    entry.setAuthor("TestAuthor");

    //Use Spring Integration util method to build a payload
    Message<SyndEntry> message = MessageBuilder.withPayload(entry).build();
    //Send Message on the channel
    filteredFeedChannel.send(message);
    Message<?> outMessage1 = splitFeedOutputChannel.receive(0);
    //Receive Message on channel
    Message<?> outMessage2 = splitFeedOutputChannel.receive(0);
    //Assert Results
    assertNotNull("Expected an output message", outMessage1);
    assertNotNull("Expected an output message", outMessage2);
    assertThat(outMessage1, hasPayload(category1));
    assertThat(outMessage2, hasPayload(category2));
  }
}
```

这个测试相当容易解释。如预期的那样，根据前面的代码中定义的原始分割器，当在通道上放置一个具有`SyndEntry`的载荷，其中有一个类别列表时，它会提取列表，将其分割，然后一个接一个地将类别放置在输出通道上。

这些例子足以开始进行 Spring Integration 测试。在 Spring Integration 上下文中，TDD 的最佳实践同样适用。实际上，除了 Spring Integration 为测试组件提供支持类之外，Spring Integration 测试并没有什么特别之处。

# 总结

我们讨论了如何测试最广泛使用的 Spring Integration 组件。始终是一个好的实践来*隔离*测试系统——这样集成时间的惊喜可以最大程度地减少。让我们结束关于测试支持的讨论，并转向下一章，我们将讨论如何管理和扩展 Spring Integration 应用程序的方法。


# 第九章：监控、管理和扩展

在上一章中，我们覆盖了最重要的方面之一——测试。我们将通过覆盖以下主题来结束对 Spring Integration 的讨论：

+   监控和管理

+   扩展

正如我们在各章中见证的那样，企业系统是异构的、脱节的，并且容易失败。使它们之间能够通信的一个重要方面是能够监控出了什么问题、哪些组件过载以及通信的关键统计信息——这将有助于提高系统的可靠性和效率。Spring 框架为监控和管理提供了相当的支持，让我们讨论如何利用它。

# 监控和管理

监控和管理操作有多种方法；例如，最常见的方法是使用 Java 的 JMX 支持，另一种选择是远程调用命令，或者监控和记录事件的发生——让我们覆盖最常用的方法。

## JMX 支持

**JMX**，是**Java 管理扩展**的缩写，不需要介绍——它是远程监控应用程序的标准方式。任何应用程序都可以提供 MBean 的实现，然后可以查询以获取暴露的管理信息。Spring Integration 提供了一个标准组件，可以用来监控通道、适配器和其他可用组件。标准的 JMX 可以扩展以获取更具体的信息。

### 先决条件

在我们可以使用 Spring Integration 的 JMX 支持之前，我们需要添加名称空间声明和 maven 依赖项：

+   **名称空间支持**：这可以通过以下代码片段添加：

    ```java
    <beans 

      xmlns:int-jmx="http://www.springframework.org/schema/integration/jmx"
      xsi:schemaLocation="http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
        http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
        http://www.springframework.org/schema/integration/jmx http://www.springframework.org/schema/integration/jmx/spring-integration-jmx.xsd">
    ```

+   **Maven 依赖**：这可以通过以下代码片段添加：

    ```java
    <dependency>
      <groupId>org.springframework.integration</groupId>
      <artifactId>spring-integration-jmx</artifactId>
      <version>${spring.integration.version}</version>
    </dependency>
    ```

+   **初始化服务器**：在传统的 Java/Spring 应用程序中，我们需要编写代码来启动平台 MBean 服务器，并导出我们的 MBeans，但 Spring 提供了标签来实现相同的任务。要创建和启动一个 MBean 服务器，只需使用以下代码行：

    ```java
      <context:mbean-server/>
    ```

    为了导出定义的 MBeans，以下代码行就足够了：

    ```java
      <context:mbean-export/>
    ```

+   **管理注解**：Spring 框架暴露了一些注解，可以用来标记将被管理或有助于管理和监控的组件。例如，`@ManagedResource`表示参与管理和监控的类，而`@ManagedAttribute`和`@ManagedOperation`分别表示类属性和操作的成员级别参与。启用`<context:mbean-export/>`将扫描并导出这些 bean 和管理节点。让我们写一个示例 MBean 并导出它，我们将在示例中使用它：

    ```java
    import javax.management.Notification;
    import org.springframework.jmx.export.annotation.ManagedAttribute;
    import org.springframework.jmx.export.annotation.ManagedOperation;
    import org.springframework.jmx.export.annotation.ManagedResource;
    import org.springframework.jmx.export.notification.NotificationPublisher;
    import org.springframework.jmx.export.notification.NotificationPublisherAware;
    import org.springframework.stereotype.Component;

    @Component
    @ManagedResource
    public class TestMBean implements NotificationPublisherAware{
      private NotificationPublisher notificationPublisher;
      private String managedData;

      @ManagedAttribute
      public String getManagedData() {
        return managedData;
      }
      @ManagedAttribute
      public void setManagedData(String managedData) {
        this.managedData = managedData;
      }
      @ManagedOperation
      public Integer testAdd(Integer num1, Integer num2) {
        notificationPublisher.sendNotification(new Notification("testAdd", this, 0));
        return num1 + num2;
      }
      @Override
      public void setNotificationPublisher(NotificationPublisher notificationPublisher) {
        this.notificationPublisher = notificationPublisher;
      }
    }
    ```

    由于使用了这些注解，这个类将被作为 MBean 导出。此外，这个类实现了`NotificationPublisherAware`，可以用来发送通知。我们将在下一个示例中看到它的使用。

+   **JConsole**：要连接和监控 JMX bean，最简单的方法是使用`Jconsole`。它随 JDK 一起提供——在`JDK_INSTALLATION_PATH/bin/Jconsole.exe`查找它。默认情况下，JConsole 将选择一个随机端口，但要对 JMX 端口进行明确控制，请使用以下参数启动 Spring Integration 应用程序：

    ```java
        -Dcom.sun.management.jmxremote
        -Dcom.sun.management.jmxremote.port=6969
        -Dcom.sun.management.jmxremote.ssl=false
        -Dcom.sun.management.jmxremote.authenticate=false
    ```

### 通知监听通道适配器

```java
<int-jmx:notification-listening-channel-adapter id="notifListener" channel="listenForNotification" object-name="com.cpandey.siexample.jmx:name=testMBean,type=TestMBean"/>
```

让我们看看使用的组件：

+   `int-jmx:notification-listening-channel-adapter`：这是通知监听通道适配器的命名空间支持。

+   `channel`：这是接收到的通知将被作为消息放入的通道。

+   `object-name`：这是发布通知的 MBean 的名称。

要测试这个适配器，请按照以下步骤操作：

1.  加载配置上下文：

    ```java
    import org.springframework.context.support.AbstractApplicationContext;
    import org.springframework.context.support.ClassPathXmlApplicationContext;

    public final class FeedsExample {
      private FeedsExample() { }

      public static void main(final String... args) {
        final AbstractApplicationContext context = new ClassPathXmlApplicationContext("classpath:META-INF/spring/integration/spring-integration-context.xml");
      }
    }
    ```

1.  启动`Jconsole`并连接到`FeedsExample`。

1.  `Jconsole`将列出`TestMBean`暴露的方法和属性。

1.  调用 add 操作，导致`Testbean`发送一个通知。

1.  负载将被放在`listenForNotification`通道上。

让我们编写一个可以触发前面代码段的小类：

```java
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.MessageChannel;

public class NotificationPublisher {
  public static void main(String[] args) {
    final AbstractApplicationContext context = new ClassPathXmlApplicationContext("classpath:META-INF/spring/integration/spring-integration-context.xml");
    try {
      Thread.sleep(60000);
    } catch (InterruptedException e) {
      //do nothing
    }
    MessageChannel publishNotification = context.getBean("publishNotification", MessageChannel.class);
    publishNotification.send(MessageBuilder.withPayload("Sample Message").build());

    MessageChannel triggerOperationChannel = context.getBean("triggerOperationChannel", MessageChannel.class);
    triggerOperationChannel.send(MessageBuilder.withPayload("Trigger Method Adapter").build());

    MessageChannel requestOperationChannel = context.getBean("requestOperationChannel", MessageChannel.class);
    requestOperationChannel.send(MessageBuilder.withPayload("Trigger Method Gateway").build());

    MessageChannel input = context.getBean("controlBusChannel", MessageChannel.class);
    String controlMessage = "@controlBusTest.controlTestOperation()";
    LOGGER.info("Sending message: " + controlMessage);
    input.send(MessageBuilder.withPayload(controlMessage).build());

    try {
      Thread.sleep(180000);
    } catch (InterruptedException e) {
      //do nothing
    }
    context.stop();
  }
}
```

前面代码段类的很简单；它加载上下文，获取通道的引用，使用 Spring Integration 支持类`MessageBuilder`构建负载，然后将其放在通道上。一旦消息放在这个通道上，将生成一个事件并发送给订阅者。引入了等待以允许`Jconsole`连接一些时间。

### 属性轮询通道适配器

正如其名称所示，它轮询由 MBean 管理的属性。需要轮询的属性名称和包含属性的 MBean 对象名称是必需的。以下代码是属性轮询通道适配器的快速示例配置：

```java
  <int:channel id="polledDataChannel"/>
  <int-jmx:attribute-polling-channel-adapter id="attribPoller" channel="polledDataChannel" object-name="com.cpandey.siexample.jmx:name=testMBean, type=TestMBean"
    attribute-name="ManagedData">
    <int:poller max-messages-per-poll="1" fixed-rate="5000"/>
  </int-jmx:attribute-polling-channel-adapter>
```

前面的配置轮询`TestMbean`的`ManagedData`属性。如果属性值发生变化，变化值将被放在通道上。我们可以有一个简单的服务，如以下代码行所示，为其提供测试：

```java
  <int:service-activator ref="commonServiceActivator" method="attributePolled" input-channel="polledDataChannel"/>
```

### 树轮询通道适配器

树轮询通道适配器本身查询 JMX 树并发送负载，负载是 MBean 对象的图形。我们可以使用查询进一步细化图形——让我们编写以下示例配置：

```java
  <int:channel id="mbeanTreeDataChannel"/>
  <int-jmx:tree-polling-channel-adapter  id="treePoller" 
    channel="mbeanTreeDataChannel"    	
    query-name="com.cpandey.siexample.jmx:type=*">
      <int:poller max-messages-per-poll="1" fixed-rate="5000"/>
  </int-jmx:tree-polling-channel-adapter>
```

我们可以使用以下代码段来触发前面的适配器：

```java
    MessageChannel triggerOperationChannel = context.getBean("triggerOperationChannel", MessageChannel.class);
    triggerOperationChannel.send(MessageBuilder.withPayload("Trigger Method Adapter").build());
```

### 调用出站网关的操作

像往常一样，`Gateway`用于将响应供进一步处理——在这种情况下，在调用操作后，响应将放回`replychannel`以供进一步处理，如下代码行所示：

```java
  <int:channel id="requestOperationChannel"/>
  <int:channel id="replyFromOperationChannel"/>
  <int-jmx:operation-invoking-outbound-gateway id="triggerOperationGateway" request-channel="requestOperationChannel" reply-channel="replyFromOperationChannel" object-name="com.cpandey.siexample.jmx:name=testMBean, type=TestMBean" operation-name="getManagedData"/>
```

```java
following lines of code:
```

```java
    MessageChannel requestOperationChannel = context.getBean("requestOperationChannel", MessageChannel.class);
    requestOperationChannel.send(MessageBuilder.withPayload("Trigger Method Gateway").build());
```

一个简单的服务激活器可以插入以验证网关返回的结果。

```java
<int:service-activator ref="commonServiceActivator" method="operationInvokedGateway" input-channel="replyFromOperationChannel"/>
```

### `MBean`导出器

那么标准 Spring 集成组件呢：`MessageChannels`、网关和其他组件？嗯，它们可以通过以下单行配置暴露出来以供监控：

```java
  <int-jmx:mbean-export 
    default-domain="com.cpandey.siexample"
    server="mbeanServer"/>
```

让我们快速看一下所使用的元素：

+   `default-domain`：这是可选的，如果留空，将使用`org.springframework.integration`作为默认域

+   `server`：这是使用`<context:mbean-server/>`创建的`mbeanServer`的引用

在结束 JMX 的讨论之前，让我们看看 JConsole 的快照。以下是我们所暴露的自定义 MBeans 和监听器的屏幕截图：

![MBean 导出器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00015.jpeg)

以下是我们定义在应用程序中的 Spring Integration 所有组件的屏幕截图：

![MBean 导出器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00016.jpeg)

我们可以观察到两个方面：

+   Spring Integration 包，列出了所有的 Spring Integration 组件

+   暴露用户定义 MBean 的 Feeds 示例

这些适配器的属性和值是非常直观的，我会留给你们去进一步探索这些。

## 跟踪消息

```java
<int:message-history/>
```

一旦添加了这个，所有这条消息传递过的组件（假设这些组件有一个`id`标签）都会添加一个审计消息。让我们看以下的例子：

```java
  <int:message-history/>

  <!-- Notification listening channel adapter -->
  <int-jmx:notification-listening-channel-adapter id="notifListener"
    channel="listenForNotification"
    object-name="com.cpandey.siexample.jmx:name=testMBean,type=TestMBean"/>

  <!-- Notification publishing channel adapter -->
  <int:channel id="publishNotification"/>
  <int-jmx:notification-publishing-channel-adapter id="publishListener"
    channel="publishNotification"
    object-name="com.cpandey.siexample.jmx:name=notificationPublisher"
    default-notification-type="default.notification.type"/>
```

在这个代码样本中，我们在开始处声明了`<int:message-history/>`。同时，注意下一个组件`notifListener`和`publishListener`有一个 ID 标签。有了这个配置，当消息通过这些组件时，会立即添加元数据。

## 线路窃听

这非常简单——它是一个拦截器，可以配置在任何通道上，并且会“窥视”通过该通道的所有消息。这可以用于调试、记录关键信息等。让我们在监听监控事件的通道上添加一个拦截器：

```java
  <int:channel id="listenForNotification">
    <int:interceptors>
      <int:wire-tap channel="logger"/>
    </int:interceptors>
  </int:channel>

<int:logging-channel-adapter 
  log-full-message="true" id="logger" level="INFO"/>
```

添加这些配置后，通过这个通道的所有消息都将被记录。

## 控制总线

我们在 Spring Integration 中有用于应用程序级消息的元素。那么使用同样的系统来触发一些动作怎么样？控制总线的背后的想法正是如此——我们可以定义通道，然后，基于该通道上的载荷，它可以调用管理操作。让我们看一个例子：

```java
  <int:channel id="controlBusChannel"/>
  <int:control-bus input-channel="controlBusChannel"/>
```

下面几行代码给出了向此总线发送控制消息的一个类：

```java
import org.apache.log4j.Logger;
import org.springframework.jmx.export.annotation.ManagedOperation;
import org.springframework.stereotype.Component;

@Component
public class ControlBusTest {
  private static final Logger LOGGER = Logger.getLogger(ControlBusTest.class);
  @ManagedOperation
  public void controlTestOperation() {
    LOGGER.info("controlTestOperation");
  }
}

MessageChannel input = context.getBean("controlBusChannel", MessageChannel.class);
String controlMessage = "@controlBusTest.controlTestOperation()";
LOGGER.info("Sending message: " + controlMessage);
input.send(MessageBuilder.withPayload(controlMessage).build());
```

有了这个，让我们结束管理和监控的讨论。在下一节中，我们将探讨应用程序设计的一个重要方面——可扩展性。

# 扩展

系统的可扩展性是最重要的非功能性需求之一。正如我们所知，扩展系统基本上有两种方式：垂直扩展和水平扩展。**垂直扩展**指的是向现有系统添加更多的处理能力——如果你内存不足，增加内存；如果 CPU 周期变短，增加一些核心或进行其他更改。挑战不大！另一方面，**水平扩展**指的是添加更多的物理节点，以分布式方式处理请求，在 DB 和消息代理组件中增加冗余。显然，这需要一个经过深思熟虑的设计。让我们看看可以用来扩展 Spring 应用程序的几种方法。

## 线程

扩展系统最常见的方法是引入并行处理。然而，在你学习如何做到这一点之前，让我们注意以下陷阱：

+   应该评估创建线程是否会有帮助

+   应根据机器能力创建线程

+   我们应该考虑其他端点的延迟

+   应该清理线程

所以让我们从一个例子开始。我们讨论了 FTP，如果有成千上万的文件可供处理，并且我们希望并行处理它们，这该如何实现？我们可以使用`TaskExecutors`，如下例所示：

```java
<bean id="ftpTaskExecutor" class="org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor">
  <property name="maxPoolSize" value="15"/>
  <property name="threadNamePrefix" value="ftpService-"/>
</bean>

<int:service-activator ref="ftpFileProcessor" method="parserFeedsFromFtp" input-channel="ftpInputChannel" output-channel="ftpOutputChannel">
    <int:poller fixed-rate="1000" receive-timeout="6000" task-executor=" ftpTaskExecutor"></int:poller>
</int:service-activator>
```

那么前面的代码中发生了什么？首先，我们定义了一个任务执行器——与 Spring 集成无关。你可以看到这里使用了 Spring 框架中的`org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor`类。然后，我们将这个与服务激活器的轮询器关联起来。现在将创建一个服务池，它将并行处理输入通道上的文件。

显而易见，Spring Integration 利用了 Spring 框架对执行器的支持。前面的代码直接使用了 bean，但 Spring 也提供了命名空间支持：

```java
<task:executor id="executor"/>
```

底层抽象是`org.springframework.core.task.TaskExecutor`。每当需要执行一个任务时，它会被提交给任务执行器；分配和回收线程是任务执行器的职责。让我们以前面示例中的轮询器为例，如果轮询通道上的元素是无状态的且可以并发处理，我们可以在那里使用执行器：

```java
<poller id="defaultPoller" fixed-delay="1000 "default="true" task-executor="executor"/>
```

如果我们有一个任务执行器来维护一个底层线程池，那么我们可以指定要维护的最大线程数，同时考虑到物理资源限制：

```java
<task:executor id="taskExecutor" pool-size="10"/>
```

## 爬取状态

当没有状态时，并发工作；那么，有哪些用例我们希望在扩展的同时管理状态是强制性的呢？例如，如果载荷太大，我们会等待所有载荷被处理，同时阻塞消费者吗？在第七章，*与 Spring Batch 集成*中，我们提到可以触发下载，然后等待下载完成的 event；在那时，消费者将启动。同样，我们有一些可以利用的方法；实际上，我们在之前的章节中已经介绍了这些内容，所以我将简要介绍如何利用持久存储来扩展状态。

### 消息存储

正如名字 suggests，我们可以暂时存储消息，直到满足某些条件。例如，如果你还记得，Aggregator 是 Spring Integration 的一个组件，它关联并暂时存储消息，直到完成条件满足。类似的概念可以用于扩展，其中任务可以暂时搁置，只有当所有其他协调成员都可用时才处理。让我们以一个 feed 的例子来说明，有些 feed 可能附带图片。文本部分将立即交付，而图片交付可能需要很长时间。我们可以配置聚合器，当所有部分到达时释放消息。我们已经在第五章，*消息流*中介绍了如何做到这一点！

### 收据

这个概念非常简单，不是等待所有组件到达，而是在某个已知位置存储一部分，并有一个指向它的指针。当最后一个块到达时，使用指针“认领”所有其他部分。显然，这适用于我们可以将有效载荷分解为独立单元并且系统可以知道最终数据包到达的情况。一旦实现，下游组件只有在所有部分都可用时才会收到数据包——它们不必等待或被阻塞以完成数据包的到达。

# 总结

在本章中，我们简要了解了 Spring Integration 框架的监控和管理方面，例如我们如何关注隐式和用户定义的集成组件，如何发送和接收事件并执行操作，还有许多其他方面。我们还介绍了如何使用线程来扩展应用程序以及几种扩展状态的方法。这使得我们的理论之旅告一段落。在下一章中，我们将编写一个端到端的应用程序，结束我们的 Spring Integration 之旅！


# 第十章：端到端的示例

我们已经涵盖了足够的内容，可以让我们在实际项目中使用 Spring Integration。让我们构建一个真正的应用程序，这将练习 Spring Integration 模块暴露的不同类型的组件。这还将作为一个刷新章节，因为我们将访问到目前为止讨论的所有概念。

让我们以 Feeds 聚合器应用程序为例；它将根据配置参数聚合 Feed，然后将其传达给感兴趣的各方。以下是我们要尝试解决的问题的大纲。这些只是为了示例，在实际场景中，我们可能不需要聚合器或分割器，或者处理序列本身可能会有所不同：

+   数据摄取可以通过：

    +   阅读 RSS 源

    +   从 FTP 服务器上的文件中读取问题

+   过滤数据：

    +   根据完成标准过滤有效/无效消息；为了简单起见，我们将过滤掉`java`问题

+   聚合消息：只是为了展示示例，我们将聚合并发布五组消息

+   分割消息：聚合消息列表将被分割并沿线发送以进行进一步处理

+   转换：

    +   将消息转换为可以写入数据库的格式

    +   将 JMS 格式的消息转换为可以放入消息队列的消息

    +   将邮件格式的消息转换，以便可以发送给订阅的收件人

+   根据消息类型路由消息；实体类型到数据库消费者，消息类型到 JMS 消费者，电子邮件消息到电子邮件发送者

+   与外部系统集成：

    +   写入数据库

    +   放置在 JMS 上

    +   使用电子邮件适配器发送邮件

+   JMX：暴露 Spring 管理监控端点

# 先决条件

在我们可以开始示例之前，我们需要以下软件来导入并运行项目：

+   一个 Java IDE（最好是 STS，但任何其他 IDE，如 Eclipse 或 NetBeans 也行）

+   JDK 1.6 及以上

+   Maven

+   FTP 服务器（这是可选的，只有在启用时才需要）

## 设置

一旦我们有了所有先决条件，按照以下步骤启动程序：

1.  检查你下载的代码包中的项目。这是一个 Maven 项目，所以使用你选择的 IDE，将其作为 Maven 项目导入。

1.  在`settings.properties`中为电子邮件、JMS 和 FTP 账户添加设置：

    ```java
    #URL of RSS feed, as example http://stackoverflow.com/feeds -Make #sure there are not copyright or legal issues in consumption of
    #feed
    feeds.url=some valid feed URL 
    #Username for e-mail account
    mail.username=yourusername
    #Password for e-mail account
    mail.password=yourpassword
    #FTP server host
    ftp.host=localhost
    #FTP port
    ftp.port=21
    #Remote directory on FTP which the listener would be observing
    ftp.remotefolder=/
    #Local directory where downloaded file should be dumped
    ftp.localfolder=C:\\Chandan\\Projects\\siexample\\ftp\\ftplocalfolder
    #Username for connecting to FTP server
    ftp.username=ftpusername
    #Password for connection to FTP server
    ftp.password=ftppassword
    #JMS broker URL
    jms.brolerurl=vm://localhost
    ```

1.  准备好一个 FTP 账户和一个电子邮件账户。

1.  从主类运行，即`FeedsExample`。

# 数据摄取：

让我们从第一步开始，数据摄取。我们配置了两个数据源：RSS 源和一个 FTP 服务器，让我们来看看这些。

## 从 RSS 源摄取数据

```java
adapter; this fetches feed from the configured url and puts it on the channel:
```

```java
<int-feed:inbound-channel-adapter 
  id="soJavaFeedAdapterForAggregator" 
  channel="fetchedFeedChannel" 
  auto-startup="true" 
  url="${feeds.url}"> 
  <int:poller 
    fixed-rate="500" max-messages-per-poll="1" />
</int-feed:inbound-channel-adapter>
```

### 提示

我将展示代码并解释它做什么，但不会详细介绍每个和每个标签，因为它们已经在相应的章节中涵盖了。

## 从 FTP 服务器摄取数据

为了让这一切工作，你需要一个配置好的 FTP 服务器。为了测试，你总是可以在本地设置一个 FTP 服务器。根据你的 FTP 服务器位置和配置参数，设置一个会话工厂：

```java
<!-- FTP Create Session-->
  <bean id="ftpClientSessionFactory" class="org.springframework.integration.ftp.session.DefaultFtpSessionFactory">
    <property name="host" value="${ftp.host}"/>
    <property name="port" value="${ftp.port}"/>
    <property name="username" value="${ftp.username}"/>
    <property name="password" value="${ftp.password}"/>
  </bean>
```

设置会话工厂后，它可以用来与 FTP 服务器建立连接。以下代码将从 FTP 的配置`远程目录`下载新文件，并将其放在`本地目录`中：

```java
<!-- FTP Download files from server and put it in local directory-->
  <int-ftp:inbound-channel-adapter 
    channel="fetchedFeedChannel"
    session-factory="ftpClientSessionFactory"
    remote-directory="${ftp.remotefolder}"
    local-directory="${ftp.localfolder}"
    auto-create-local-directory="true"
    delete-remote-files="true"
    filename-pattern="*.txt"
    local-filename-generator-expression="#this.toLowerCase() + '.trns'">
    <int:poller fixed-rate="1000"/>
  </int-ftp:inbound-channel-adapter>
```

## 过滤数据

馈送和 FTP 适配器获取馈送并将其放入`获取馈送通道`。让我们配置一个过滤器，在读取馈送时只允许 Java 相关的问题。它将从一个通道`获取馈送通道`读取馈送，并将过滤后的馈送传递给通道`获取馈送通道用于聚合器`。以下代码片段是 Spring 配置：

```java
  <bean id="filterSoFeedBean" class="com.cpandey.siexample.filter.SoFeedFilter"/>
  <!--Filter the feed which are not for Java category -->
<int:filter input-channel="fetchedFeedChannel" output-channel="fetchedFeedChannelForAggregatior" ref="filterSoFeedBean" method="filterFeed"/>
```

以下是包含过滤逻辑的 JavaBean 类：

```java
import java.util.List;
import org.apache.log4j.Logger;
import org.springframework.messaging.Message;
import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedFilter {
  private static final Logger LOGGER = Logger.getLogger(SoFeedFilter.class);
  public boolean filterFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    List<SyndCategoryImpl> categories=entry.getCategories();
    if(categories!=null&&categories.size()>0){
      for (SyndCategoryImpl category: categories) {
        if(category.getName().equalsIgnoreCase("java")){
          LOGGER.info("JAVA category feed");
          return true;
        }
      }
    }
    return false;
  }
}
```

# 聚合器

聚合器用于展示聚合器的使用。聚合器被插在过滤器的输出通道上，即`获取馈送通道用于聚合器`。我们将使用聚合器的所有三个组件：关联、完成和聚合器。让我们声明 bean：

```java
  <bean id="soFeedCorrelationStrategyBean" class="com.cpandey.siexample.aggregator.CorrelationStrategy"/>

  <bean id="sofeedCompletionStrategyBean" class="com.cpandey.siexample.aggregator.CompletionStrategy"/>

  <bean id="aggregatorSoFeedBean" class="com.cpandey.siexample.aggregator.SoFeedAggregator"/>
```

在我们定义了聚合器的三个关键组件之后，让我们定义一个组件，它将一组五个馈送进行聚合，然后仅在下一个通道发布：

```java
  <int:aggregator input-channel="fetchedFeedChannelForAggregatior"
    output-channel="aggregatedFeedChannel" ref="aggregatorSoFeedBean"
    method="aggregateAndPublish" release-strategy="sofeedCompletionStrategyBean"
    release-strategy-method="checkCompleteness" correlation-strategy="soFeedCorrelationStrategyBean"
    correlation-strategy-method="groupFeedsBasedOnCategory"
    message-store="messageStore" expire-groups-upon-completion="true">
    <int:poller fixed-rate="1000"></int:poller>
  </int:aggregator>
```

## 关联 bean

如果你记得，关联 bean 持有分组“相关”项的策略。我们将简单地使用馈送的类别来分组消息：

```java
import java.util.List;
import org.apache.log4j.Logger;
import org.springframework.messaging.Message;
import com.sun.syndication.feed.synd.SyndCategoryImpl;
import com.sun.syndication.feed.synd.SyndEntry;

public class CorrelationStrategy {
  private static final Logger LOGGER = Logger.getLogger(CorrelationStrategy.class);

  //aggregator's method should expect a Message<?> and return an //Object.
  public Object groupFeedsBasedOnCategory(Message<?> message) {
    //Which messages will be grouped in a bucket 
    //-say based on category, based on some ID etc.
    if(message!=null){
      SyndEntry entry = (SyndEntry)message.getPayload();
      List<SyndCategoryImpl> categories=entry.getCategories();
      if(categories!=null&&categories.size()>0){
        for (SyndCategoryImpl category: categories) {
          //for simplicity, lets consider the first category
          LOGGER.info("category "+category.getName());
          return category.getName();
        }
      }
    }
    return null;
  }
}
```

## 完成 bean

我们已经关联了消息，但我们将会持有列表多久？这将由完成标准来决定。让我们设定一个简单的标准，如果有五个同一类别的馈送，那么释放它进行进一步处理。以下是实现这个标准的类：

```java
import java.util.List;
import org.apache.log4j.Logger;
import com.sun.syndication.feed.synd.SyndEntry;

public class CompletionStrategy {
  private static final Logger LOGGER = Logger.getLogger(CompletionStrategy.class);
  //Completion strategy is used by aggregator to decide whether all //components has
  //been aggregated or not method should expect a java.util.List 
  //Object returning a Boolean value
  public boolean checkCompleteness(List<SyndEntry> messages) {
    if(messages!=null){
      if(messages.size()>4){
        LOGGER.info("All components assembled, releasing aggregated message");
        return true;
      }
    }
    return false;
  }

}
```

## 聚合器 bean

馈送将会被关联，在满足完成标准后，聚合器将在下一个端点返回列表。我们之前已经定义了关联策略和完成标准，让我们看看聚合器的代码：

```java
import java.util.List;
import org.apache.log4j.Logger;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedAggregator {
  private static final Logger LOGGER = Logger.getLogger(SoFeedAggregator.class);
  public List<SyndEntry> aggregateAndPublish( List<SyndEntry> messages) {
    LOGGER.info("SoFeedAggregator -Aggregation complete");
    return messages;
  }
}
```

# 分割器

```java
<int:splitter ref="splitterSoFeedBean" method="splitAndPublish" input-channel="aggregatedFeedChannel" output-channel="splittedFeedChannel" />
```

包含分割逻辑的 JavaBean：

```java
import java.util.List;
import com.sun.syndication.feed.synd.SyndEntry;
public class SoFeedSplitter {
  public List<SyndEntry> splitAndPublish(List<SyndEntry> message) {
    //Return one message from list at a time -this will be picked up //by the processor
    return message;
  }
}
```

# 转换

现在我们有了 RSS 格式的馈送，让我们将其转换为适当的格式，以便负责将馈送持久化到数据库、将其放入 JMS 通道和发送邮件的端点可以理解。分割器将一次在通道`分割馈送通道`上放置一个消息。让我们将其声明为发布-订阅通道，并附加三个端点，这些将是我们的转换器。如下配置发布-订阅通道：

```java
<int:publish-subscribe-channel id="splittedFeedChannel"/>
```

我们使用的三个转换器的配置如下：

```java
  <bean id="feedDbTransformerBean" class="com.cpandey.siexample.transformer.SoFeedDbTransformer" />

  <bean id="feedJMSTransformerBean" class="com.cpandey.siexample.transformer.SoFeedJMSTransformer" />

  <bean id="feedMailTransformerBean" class="com.cpandey.siexample.transformer.SoFeedMailTransformer" />
```

## 数据库转换器

让我们从 Spring Integration 和包含转换逻辑的 Java 类编写转换器组件：

```java
<int:transformer id="dbFeedTransformer" ref="feedDbTransformerBean" input-channel="splittedFeedChannel" method="transformFeed" output-channel="transformedChannel"/>

import org.apache.log4j.Logger;
import org.springframework.messaging.Message;
import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedDbTransformer {
  private static final Logger LOGGER = Logger.getLogger(SoFeedDbTransformer.class);

  public SoFeed transformFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    SoFeed soFeed=new SoFeed();
    soFeed.setTitle(entry.getTitle());
    soFeed.setDescription(entry.getDescription().getValue());
    soFeed.setCategories(entry.getCategories());
    soFeed.setLink(entry.getLink());
    soFeed.setAuthor(entry.getAuthor());
    LOGGER.info("JDBC :: "+soFeed.getTitle());
    return soFeed;
  }
}
```

## JMS 转换器

以下是 JMS 转换器组件声明的代码以及相应的 JavaBean：

```java
<int:transformer id="jmsFeedTransformer" ref="feedJMSTransformerBean" 
  input-channel="splittedFeedChannel" 
  method="transformFeed" 
  output-channel="transformedChannel"/>

import org.apache.log4j.Logger;
import org.springframework.messaging.Message;
import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndEntry;
public class SoFeedJMSTransformer {
  private static final Logger LOGGER = Logger.getLogger(SoFeedJMSTransformer.class);

  public String transformFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    SoFeed soFeed=new SoFeed();
    soFeed.setTitle(entry.getTitle());
    soFeed.setDescription(entry.getDescription().getValue());
    soFeed.setCategories(entry.getCategories());
    soFeed.setLink(entry.getLink());
    soFeed.setAuthor(entry.getAuthor());
    //For JSM , return String 
    LOGGER.info("JMS"+soFeed.getTitle());
    return soFeed.toString();
  }
}
```

## 邮件转换器

最后，让我们编写邮件转换器的配置和代码：

```java
<int:transformer id="mailFeedTransformer" ref="feedMailTransformerBean" 
  input-channel="splittedFeedChannel"
  method="transformFeed" 
  output-channel="transformedChannel"/>

import java.util.Date;
import org.apache.log4j.Logger;
import org.springframework.mail.MailMessage;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.messaging.Message;
import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndEntry;

public class SoFeedMailTransformer {
  private static final Logger LOGGER = Logger.getLogger(SoFeedMailTransformer.class);

  public MailMessage transformFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    SoFeed soFeed=new SoFeed();
    soFeed.setTitle(entry.getTitle());
    soFeed.setDescription(entry.getDescription().getValue());
    soFeed.setCategories(entry.getCategories());
    soFeed.setLink(entry.getLink());
    soFeed.setAuthor(entry.getAuthor());

    //For Mail return MailMessage
    MailMessage msg = new SimpleMailMessage();
    msg.setTo("emailaddress");
    msg.setFrom("emailaddress");
    msg.setSubject("Subject");
    msg.setSentDate(new Date());
    msg.setText("Mail Text");
    LOGGER.info("Mail Message"+soFeed.getTitle());

     return msg;
  }
}
```

# 路由器

在将消息转换为适当格式后，转换器将消息放入`transformedChannel`通道。我们将处理三种不同类型的消息，这些消息将由不同的端点处理。我们可以使用载荷路由器，根据载荷类型将其路由到不同的组件：

```java
    <int:payload-type-router input-channel="transformedChannel" 
      default-output-channel="logChannel">
    <int:mapping type="com.cpandey.siexample.pojo.SoFeed"
      channel="jdbcChannel" />
    <int:mapping type="java.lang.String" 
      channel="jmsChannel" />
    <int:mapping type="org.springframework.mail.MailMessage" 
      channel="mailChannel" />
    </int:payload-type-router>
```

# 集成

现在是实际集成的时刻！一旦路由器将消息路由到适当的端点，它应该被这些端点处理。例如，它可以被持久化到数据库，通过 JMS 通道发送，或者作为电子邮件发送。根据载荷类型，路由器将消息放入`jdbcChannel`、`jmsChannel`或`mailChannel`中的一个通道。如果它无法理解载荷，它将把消息路由到`logChannel`。让我们从与`jdbcChannel`通道关联的端点开始，该通道用于数据库集成。

## 数据库集成

在本节中，我们将编写代码以从数据库添加和查询数据。在我们将 Spring Integration 的适配器编写之前，让我们先完成基本设置。

### 先决条件

显而易见，我们需要一个数据库来存储数据。为了简化，我们将使用内存数据库。我们还需要配置 ORM 提供者、事务以及其他与数据库一起使用的方面：

+   嵌入式数据库的声明：

    ```java
      <jdbc:embedded-database id="dataSource" type="H2"/>
    ```

+   事务管理器的声明：

    ```java
      <bean id="transactionManager" class="org.springframework.orm.jpa.JpaTransactionManager">
        <constructor-arg ref="entityManagerFactory" />
      </bean>
    ```

+   实体管理工厂的声明：

    ```java
    <bean id="entityManagerFactory"
      class="org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean">
      <property name="dataSource"  ref="dataSource" />
      <property name="jpaVendorAdapter" ref="vendorAdaptor" />
      <property name="packagesToScan" value="com.cpandey.siexample.pojo"/>
      </bean>
    ```

+   实体管理器的声明：

    ```java
    <bean id="entityManager" class="org.springframework.orm.jpa.support.SharedEntityManagerBean">
        <property name="entityManagerFactory" ref="entityManagerFactory"/>
      </bean>
    ```

+   抽象供应商适配器的声明：

    ```java
    <bean id="abstractVendorAdapter" abstract="true">
      <property name="generateDdl" value="true" />
      <property name="database"    value="H2" />
      <property name="showSql"     value="false"/>
    </bean>
    ```

+   实际供应商适配器的声明，在我们的案例中，它是 hibernate：

    ```java
      <bean id="vendorAdaptor" class="org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter"
        parent="abstractVendorAdaptor">
      </bean>
    ```

### 网关

让我们定义一个网关，它将插入调用方法来插入数据流，然后从数据库中读取它们：

```java
<int:gateway id="feedService"
  service-interface="com.cpandey.siexample.service.FeedService"
  default-request-timeout="5000"
  default-reply-timeout="5000">
  <int:method name="createFeed"
    request-channel="createFeedRequestChannel"/>
  <int:method name="readAllFeed"
    reply-channel="readFeedRequestChannel"/>
</int:gateway>
```

网关的 Bean 定义如下：

```java
import java.util.List;
import com.cpandey.siexample.pojo.FeedEntity;
public interface FeedService {
  FeedEntity createFeed(FeedEntity feed);
  List<FeedEntity> readAllFeed();
}
```

### 服务激活器

此服务激活器被连接到`jdbcChannel`通道。当消息到达时，它的`persistFeedToDb`方法被调用，该方法使用前面的网关将数据流持久化：

```java
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.integration.annotation.MessageEndpoint;
import org.springframework.integration.annotation.ServiceActivator;
import com.cpandey.siexample.pojo.FeedEntity;
import com.cpandey.siexample.pojo.SoFeed;

@MessageEndpoint
public class PersistFeed {

  private static final Logger LOGGER = Logger.getLogger(PersistFeed.class);

  @Autowired FeedService feedService;
  @ServiceActivator
  public void persistFeedToDb(SoFeed feed) {
    //This will write to output channel of gateway
    //From there this will be picked by updating adapter
    feedService.createFeed(new FeedEntity(feed.getTitle()));
  }

  @ServiceActivator
  public void printFeed(FeedEntity feed) {
    //Print the feed fetched by retrieving adapter
    LOGGER.info("Feed Id"+feed.getId()+" Feed Title "+feed.getTitle());
  }
}
```

### 用于更新和读取数据流的网关：

最后，我们将 Spring Integration 更新和检索出站网关的功能集成进来，以持久化和从数据库中读取数据流：

```java
  <int-jpa:updating-outbound-gateway 
    entity-manager-factory="entityManagerFactory"
    request-channel="createFeedRequestChannel" 
    entity-class="com.cpandey.siexample.pojo.FeedEntity" 
    reply-channel="printAllFeedChannel">
    <int-jpa:transactional transaction-manager="transactionManager" />
  </int-jpa:updating-outbound-gateway>

  <int-jpa:retrieving-outbound-gateway 
    entity-manager-factory="entityManagerFactory"
    request-channel="readFeedRequestChannel"
    jpa-query="select f from FeedEntity f order by f.title asc" 
    reply-channel="printAllFeedChannel">
  </int-jpa:retrieving-outbound-gateway>
```

## 发送邮件

我们可以使用 Spring Integration 邮件出站通道适配器来发送邮件。它需要对邮件发送者类的引用，该类已按照以下方式配置：

+   Spring Integration 发送邮件的组件：

    ```java
      <int-mail:outbound-channel-adapter channel="mailChannel" mail-sender="mailSender"/>
    ```

    如前面的配置所示，此适配器被连接到`mailChannel`—路由器将消息路由到的其他通道之一。

+   前一个组件使用的邮件发送者：

    ```java
      <bean id="mailSender" class="org.springframework.mail.javamail.JavaMailSenderImpl">
        <property name="javaMailProperties">
          <props>
            <prop key="mail.smtp.auth">true</prop>
            <prop key="mail.smtp.starttls.enable">true</prop>
            <prop key="mail.smtp.host">smtp.gmail.com</prop>
            <prop key="mail.smtp.port">587</prop>
          </props>
        </property>
        <property name="username" value="${mail.username}" />
        <property name="password" value="${mail.password}" />
      </bean>
    ```

## 将消息放入 JMS 队列

最后，让我们使用出站通道适配器将消息放入 JMS 队列，此适配器轮询`jmsChannel`通道以获取消息，每当路由器将消息路由至此处，它都会将其放入`destination`队列：

```java
  <int-jms:outbound-channel-adapter connection-factory="connectionFactory" channel="jmsChannel" destination="feedInputQueue" />
```

为了测试队列中的消息，让我们添加一个简单的服务激活器：

```java
<int:service-activator ref="commonServiceActivator" method="echoJmsMessageInput" input-channel="jmsProcessedChannel"/>
```

从之前的配置中可以看出，我们需要`destination`和`connection-factory`，让我们来配置这些：

```java
  <bean id="feedInputQueue" class="org.apache.activemq.command.ActiveMQQueue">
    <constructor-arg value="queue.input"/>
  </bean>

  <bean id="connectionFactory" 
    class="org.springframework.jms.connection.CachingConnectionFactory">
    <property name="targetConnectionFactory">
      <bean class="org.apache.activemq.ActiveMQConnectionFactory">
        <property name="brokerURL" value="${jms.brokerurl}"/>
      </bean>
    </property>
    <property name="sessionCacheSize" value="10"/>
    <property name="cacheProducers" value="false"/>
  </bean>
```

# 导出为 MBean

最后，让我们添加代码以导出作为 MBean 使用的组件，这可以通过 JConsole 或其他 JMX 工具进行监控：

```java
  <int-jmx:mbean-export 
    default-domain="com.cpandey.siexample"
    server="mbeanServer"/>
```

# 摘要

在本章中，我们覆盖了一个端到端的示例；我希望这很有用，并且能在一个地方刷新概念和完整的用例。有了这个，我们的 Spring Integration 之旅就结束了。我希望你喜欢它！

我们覆盖了 Spring Integration 框架的绝大多数常用特性，并介绍了足够的内容来获得动力。如果这本书让你对使用 Spring Integration 感到兴奋，那么你的下一个目的地应该是[`docs.spring.io/spring-integration/reference/htmlsingle`](http://docs.spring.io/spring-integration/reference/htmlsingle)官方参考资料。
