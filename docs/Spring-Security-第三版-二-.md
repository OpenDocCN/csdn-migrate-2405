# Spring Security 第三版（二）

> 原文：[`zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5`](https://zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 Spring Data 进行身份验证

在上一章中，我们介绍了如何利用 Spring Security 内置的 JDBC 支持。在本章中，我们将介绍 Spring Data 项目，以及如何利用 JPA 对关系数据库进行身份验证。我们还将探讨如何使用 MongoDB 对文档数据库进行身份验证。本章的示例代码基于第四章的 Spring Security 设置，*基于 JDBC 的身份验证*，并已更新以去除对 SQL 的需求，并使用 ORM 处理所有数据库交互。

在本章中，我们将介绍以下主题：

+   与 Spring Data 项目相关的一些基本概念

+   使用 Spring Data JPA 对关系数据库进行身份验证

+   使用 Spring Data MongoDB 对文档数据库进行身份验证

+   如何为处理 Spring Data 集成提供更多灵活性自定义 Spring Security

+   理解 Spring Data 项目

Spring Data 项目的使命是为数据访问提供熟悉的、一致的基于 Spring 的编程模型，同时保留底层数据提供商的独特特性。

以下是 Spring Data 项目的一些强大功能：

+   强大的仓库和自定义对象映射抽象

+   从仓库方法名称派生动态查询

+   实现领域基础类，提供基本属性

+   支持透明审计（创建和最后更改）

+   集成自定义仓库代码的能力

+   通过基于 Java 的配置和自定义 XML 命名空间实现简单的 Spring 集成

+   与 Spring MVC 控制器的高级集成

+   跨存储持久性的实验性支持

该项目简化了数据访问技术、关系型和非关系型数据库、映射框架和基于云的数据服务的使用。这个伞形项目包含了许多特定于给定数据库的子项目。这些项目是在与这些令人兴奋的技术背后的许多公司和开发人员合作开发的。还有许多由社区维护的模块和其他相关模块，包括**JDBC 支持**和**Apache Hadoop**。

以下表格描述了组成 Spring Data 项目的的主要模块：

| **模块** | **描述** |
| --- | --- |
| Spring Data Commons | 将核心 Spring 概念应用于所有 Spring Data 项目 |
| Spring Data Gemfire | 提供从 Spring 应用程序轻松配置和访问 Gemfire 的支持 |
| Spring Data JPA | 使实现基于 JPA 的仓库变得容易 |
| Spring Data Key Value | 基于映射的仓库和 SPIs，可轻松构建键值存储的 Spring Data 模块 |
| Spring Data LDAP | 为 Spring LDAP 提供 Spring Data 仓库支持 |
| Spring Data MongoDB | 基于 Spring 的、对象-文档支持以及 MongoDB 的仓库 |
| Spring Data REST | 将 Spring Data 存储库导出为基于超媒体的 RESTful 资源 |
| Spring Data Redis | 为 Spring 应用程序提供易于配置和访问 Redis 的功能 |
| Spring Data for Apache Cassandra | 适用于 Apache Cassandra 的 Spring Data 模块 |
| Spring Data for Apache Solr | 适用于 Apache Solr 的 Spring Data 模块 |

# Spring Data JPA

Spring Data JPA 项目旨在显著改进数据访问层的 ORM 实现，通过减少实际所需的工作量。开发者只需编写存储库接口，包括自定义查找方法，Spring 将自动提供实现。

以下是一些 Spring Data JPA 项目的特定强大功能：

+   为基于 Spring 和 JPA 构建存储库提供高级支持

+   支持**Querydsl**谓词，因此也支持类型安全的 JPA 查询

+   对领域类进行透明审计

+   分页支持、动态查询执行以及集成自定义数据访问代码的能力

+   在启动时验证`@Query`注解的查询

+   支持基于 XML 的实体映射

+   通过引入`@EnableJpaRepositories`实现基于`JavaConfig`的存储库配置

# 更新我们的依赖项

我们已经包括了本章所需的所有依赖项，所以您不需要对`build.gradle`文件进行任何更新。然而，如果您只是将 Spring Data JPA 支持添加到您自己的应用程序中，您需要在`build.gradle`文件中添加`spring-boot-starter-data-jpa`作为依赖项，如下所示：

```java
    //build.gradle

    dependencies {
       ...
    // REMOVE: compile('org.springframework.boot:spring-boot-starter-jdbc')
 compile('org.springframework.boot:spring-boot-starter-data-jpa')       ...
    }
```

请注意我们移除了`spring-boot-starter-jdbc`依赖。`spring-boot-starter-data-jpa`依赖将包含所有必要的依赖项，以便将我们的领域对象与使用 JPA 的嵌入式数据库连接。

# 将 JBCP 日历更新为使用 Spring Data JPA

为了熟悉 Spring Data，我们首先将 JBCP 日历 SQL 转换为使用 ORM，使用 Spring Data JPA 启动器。

创建和维护 SQL 可能相当繁琐。在前几章中，当我们想在数据库中创建一个新的`CalendarUser`表时，我们必须编写大量的样板代码，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/
    dataaccess/JdbcCalendarUserDao.java

    public int createUser(final CalendarUser userToAdd) {
    if (userToAdd == null) {
         throw new IllegalArgumentException("userToAdd cannot be null");
    }
    if (userToAdd.getId() != null) {
         throw new IllegalArgumentException("userToAdd.getId() must be 
         null when creating a 
         "+CalendarUser.class.getName());
    }
 KeyHoldener keyHolder = new GeratedKeyHolder(); this.jdbcOperations.update(new PreparedStatementCreator() { public PreparedStatement createPreparedStatement
       (Connection connection)
       throws SQLException { PreparedStatement ps = connection.prepareStatement("insert into 
         calendar_users (email, password, first_name, last_name) 
         values (?, ?, ?, ?)", new String[] {  
          "id" });
 ps.setString(1, userToAdd.getEmail()); ps.setString(2, userToAdd.getPassword()); ps.setString(3, userToAdd.getFirstName()); ps.setString(4, userToAdd.getLastName()); return ps; } }, keyHolder);    return keyHolder.getKey().intValue();
    }
```

创建这个对象，技术上我们需要 12 行代码来执行操作。

现在，使用 Spring Data JPA，相同的实现可以减少到以下代码片段：

```java
    //src/main/java/com/packtpub/springsecurity/dataaccess/JpaCalendarUserDao.java

    public int createUser(final CalendarUser userToAdd) {
    if (userToAdd == null) {
         throw new IllegalArgumentException("userToAdd cannot be null");
    }
    if (userToAdd.getId() != null) {
         throw new IllegalArgumentException("userToAdd.getId() 
         must be null when creating a "+CalendarUser.class.getName());
    }
 Set<Role> roles = new HashSet<>(); roles.add(roleRepository.findOne(0)); userToAdd.setRoles(roles); CalendarUser result = repository.save(userToAdd); repository.flush();     return result.getId();
    }
```

现在，使用 JPA 创建这个对象，技术上我们需要五行代码来执行操作。我们现在需要的代码量不到原来执行相同操作的一半。

# 重新配置数据库配置

首先，我们将转换当前的 JBCP 日历项目。让我们先重新配置数据库。

我们可以首先删除 `DataSourceConfig.java` 文件，因为我们将会利用 Spring Boot 对嵌入式 H2 数据库的内置支持。我们还需要删除 `JavaConfig.java` 文件中对 `DataSourceConfig.java` 的引用，因为目前 `@Import` 注解中有对 `JavaConfig.java` 的引用。

# 初始化数据库

现在，我们可以删除 `src/main/resources/database` 目录及其目录下的所有内容。这个目录包含几个 `.sql` 文件，我们将合并并将它们移动到下一步：

现在，我们需要创建一个 `data.sql` 文件，该文件将包含我们的种子数据，如下所示：

```java
    //src/main/resources/data.sql:
```

+   查看以下 SQL 语句，描述了 `user1` 的密码：

```java
        insert into calendar_users(id,username,email,password,
        first_name,last_name) 
        values(0,'user1@example.com','user1@example.com',
        '$2a$04$qr7RWyqOnWWC1nwotUW1nOe1RD5.
        mKJVHK16WZy6v49pymu1WDHmi','User','1');
```

+   查看以下 SQL 语句，描述了 `admin1` 的密码：

```java
        insert into calendar_users(id,username,email,password,
        first_name,last_name) 
        values (1,'admin1@example.com','admin1@example.com',
        '$2a$04$0CF/Gsquxlel3fWq5Ic/ZOGDCaXbMfXYiXsviTNMQofWRXhvJH3IK',
        'Admin','1');
```

+   查看以下 SQL 语句，描述了 `user2` 的密码：

```java
        insert into calendar_users(id,username,email,password,first_name,
        last_name)
        values (2,'user2@example.com','user2@example.com',
        '$2a$04$PiVhNPAxunf0Q4IMbVeNIuH4M4ecySWHihyrclxW..PLArjLbg8CC',
        'User2','2');
```

+   查看以下 SQL 语句，描述用户角色：

```java
        insert into role(id, name) values (0, 'ROLE_USER');
        insert into role(id, name) values (1, 'ROLE_ADMIN');
```

+   在这里，`user1` 有一个角色：

```java
        insert into user_role(user_id,role_id) values (0, 0);
```

+   在这里，`admin1` 有两个角色：

```java
        insert into user_role(user_id,role_id) values (1, 0);
        insert into user_role(user_id,role_id) values (1, 1);
```

+   查看以下 SQL 语句，描述事件：

```java
        insert into events (id,when,summary,description,owner,attendee)
        values (100,'2017-07-03 20:30:00','Birthday Party',
        'This is going to be a great birthday',0,1);
        insert into events (id,when,summary,description,owner,attendee) 
        values (101,'2017-12-23 13:00:00','Conference Call','Call with 
        the client',2,0);
        insert into events (id,when,summary,description,owner,attendee) 
        values (102,'2017-09-14 11:30:00','Vacation',
        'Paragliding in Greece',1,2);
```

现在，我们可以更新应用程序属性，在`src/main/resources/application.yml`文件中定义嵌入式数据库属性，如下所示：

```java
    # Embedded Database
    datasource:
    url: jdbc:h2:mem:dataSource;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
    driverClassName: org.h2.Driver
    username: sa
    password:
    continue-on-error: true
 jpa: database-platform: org.hibernate.dialect.H2Dialect show-sql: true hibernate: ddl-auto: create-drop
```

在此阶段，我们已经移除了旧的数据库配置并添加了新的配置。应用程序在此阶段无法运行，但仍然可以将其视为我们在转换下一步之前的标记点。

您的代码现在应该看起来像 `calendar05.01-calendar`。

# SQL 到 ORM 的重构

从 SQL 转换到 ORM 实现的重构比你想象的要简单。重构的大部分工作涉及删除以 SQL 形式存在的冗余代码。在下一部分，我们将把 SQL 实现重构成 JPA 实现。

为了让 JPA 将我们的领域对象映射到数据库，我们需要对我们的领域对象进行一些映射。

# 使用 JPA 映射领域对象

查看以下步骤，了解如何映射领域对象：

1.  让我们首先映射我们的 `Event.java` 文件，以便所有领域对象都将使用 JPA，如下所示：

```java
//src/main/java/com/packtpub/springsecurity/domain/Event.java

import javax.persistence.*; @Entity @Table(name = "events") public class Event implements Serializable{
 @Id @GeneratedValue(strategy = GenerationType.AUTO) private Integer id;
@NotEmpty(message = "Summary is required")
private String summary;
@NotEmpty(message = "Description is required")
private String description;
@NotNull(message = "When is required")
private Calendar when;
@NotNull(message = "Owner is required")
 @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="owner", referencedColumnName="id") private CalendarUser owner;
 @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="attendee", referencedColumnName="id") private CalendarUser attendee;
```

1.  我们需要创建一个 `Role.java` 文件，内容如下：

```java
//src/main/java/com/packtpub/springsecurity/domain/Role.java

import javax.persistence.*;
@Entity @Table(name = "role") public class Role implements Serializable {
 @Id @GeneratedValue(strategy = GenerationType.AUTO) private Integer id;
private String name;
 @ManyToMany(fetch = FetchType.EAGER, mappedBy = "roles") private Set<CalendarUser> users;
```

1.  `Role` 对象将用于将权限映射到我们的 `CalendarUser` 表。现在我们已经有一个 `Role.java` 文件，让我们来映射我们的 `CalendarUser.java` 文件：

```java
//src/main/java/com/packtpub/springsecurity/domain/CalendarUser.java

import javax.persistence.*;
import java.io.Serializable;
import java.util.Set;
@Entity @Table(name = "calendar_users") public class CalendarUser implements Serializable {
 @Id @GeneratedValue(strategy = GenerationType.AUTO)   private Integer id;
   private String firstName;
   private String lastName;
   private String email;
   private String password;
 @ManyToMany(fetch = FetchType.EAGER) @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id")) private Set<Role> roles;
```

在此阶段，我们已经用所需的 JPA 注解映射了我们的领域对象，包括 `@Entity` 和 `@Table` 以定义 RDBMS 的位置，以及结构、引用和关联映射注解。

在此阶段，应用程序将无法运行，但这仍然可以被视为我们在继续转换下一步之前的标记点。

您应该从 `chapter05.02-calendar` 的源代码开始。

# Spring Data 仓库

接下来，我们将通过执行以下步骤向 Spring Data 添加所需接口，以将我们所需的 CRUD 操作映射到嵌入式数据库：

1.  我们首先在新的包中添加一个新的接口，该包将是`com.packtpub.springsecurity.repository`。新文件将称为`CalendarUserRepository.java`，如下所示：

```java
        //com/packtpub/springsecurity/repository/CalendarUserRepository.java

        package com.packtpub.springsecurity.repository;
        import com.packtpub.springsecurity.domain.CalendarUser;
        import org.springframework.data.jpa.repository.JpaRepository;

        public interface CalendarUserRepository
               extends JpaRepository<CalendarUser, Integer> {
           CalendarUser findByEmail(String email);
        }
```

这将允许我们对`CalendarUser`对象执行标准的 CRUD 操作，如`find()`、`save()`和`delete()`。

1.  现在我们可以继续在同一存储库包中添加一个新的接口，该包将是`com.packtpub.springsecurity.repository`，新文件将称为`EventRepository.java`：

```java
            //com/packtpub/springsecurity/repository/EventRepository.java

            package com.packtpub.springsecurity.repository;
            import com.packtpub.springsecurity.domain.Event;
            import org.springframework.data.jpa.repository.JpaRepository;

            public interface EventRepository extends JpaRepository<Event, 
            Integer> {}
```

这将允许我们对`Event`对象执行标准的 CRUD 操作，如`find()`、`save()`和`delete()`。

1.  最后，我们将在同一存储库包中添加一个新的接口，该包将是`com.packtpub.springsecurity.repository`，新文件将称为`RoleRepository.java`。这个`CrudRepository`接口将用于管理与给定的`CalendarUser`相关的安全角色的`Role`对象：

```java
            //com/packtpub/springsecurity/repository/

            package com.packtpub.springsecurity.repository;
            import com.packtpub.springsecurity.domain.Event;
            import org.springframework.data.jpa.repository.JpaRepository;

            public interface RoleRepository extends JpaRepository<Role, 
            Integer> {}
```

这将允许我们对`Role`对象执行标准的 CRUD 操作，如`find()`、`save()`和`delete()`。

# 数据访问对象

我们需要将`JdbcEventDao.java`文件重命名为`JpaEventDao.java`，以便我们可以用新的 Spring Data 代码替换 JDBC SQL 代码。让我们来看看以下步骤：

1.  具体来说，我们需要添加新的`EventRepository`接口，并用新的 ORM 存储库替换 SQL 代码，如下所示：

```java
        //com/packtpub/springsecurity/dataaccess/JpaEventDao.java

        package com.packtpub.springsecurity.dataaccess;
        import com.packtpub.springsecurity.domain.CalendarUser;
        import com.packtpub.springsecurity.domain.Event;
 import com.packtpub.springsecurity.repository.EventRepository;        import org.springframework.beans.factory.annotation.Autowired;
        import org.springframework.data.domain.Example;
        import org.springframework.stereotype.Repository;
        import org.springframework.transaction.annotation.Transactional;
        ...
        @Repository
         public class JpaEventDao implements EventDao {
 private EventRepository repository;           @Autowired
 public JpaEventDao(EventRepository repository) { if (repository == null) { throw new IllegalArgumentException("repository 
                    cannot be null"); } this.repository = repository;           }
           @Override
           @Transactional(readOnly = true)
           public Event getEvent(int eventId) {
 return repository.findOne(eventId);           }
           @Override
           public int createEvent(final Event event) {
               ...
               final Calendar when = event.getWhen();
               if(when == null) {
                   throw new IllegalArgumentException("event.getWhen() 
                   cannot be null");
               }
 Event newEvent = repository.save(event);              ...
           }
           @Override
           @Transactional(readOnly = true)
           public List<Event> findForUser(final int userId) {
                Event example = new Event();
 CalendarUser cu = new CalendarUser(); cu.setId(userId); example.setOwner(cu);               return repository.findAll(Example.of(example));
           }
           @Override
           @Transactional(readOnly = true)
           public List<Event> getEvents() {
 return repository.findAll();           }
        }
```

1.  在此阶段，我们需要重构 DAO 类以支持我们创建的新`CrudRepository`接口。让我们从重构`JdbcCalendarUserDao.java`文件开始。首先，我们可以将文件重命名为`JpaCalendarUserDao.java`，以表示此文件使用 JPA，而不是标准的 JDBC：

```java
        //com/packtpub/springsecurity/dataaccess/JpaCalendarUserDao.java

        package com.packtpub.springsecurity.dataaccess;
        ... omitted for brevity ...
        @Repository
        public class JpaCalendarUserDao
               implements CalendarUserDao {
 private CalendarUserRepository userRepository; private RoleRepository roleRepository; @Autowired public JpaCalendarUserDao(CalendarUserRepository repository, RoleRepository roleRepository) { if (repository == null) { throw new IllegalArgumentException("repository 
                   cannot be null"); } if (roleRepository == null) { throw new IllegalArgumentException("roleRepository 
                   cannot be null"); } this. userRepository = repository; this.roleRepository = roleRepository; }           @Override
           @Transactional(readOnly = true)
           public CalendarUser getUser(final int id) {
 return userRepository.findOne(id);           }
           @Override
           @Transactional(readOnly = true)
           public CalendarUser findUserByEmail(final String email) {
               if (email == null) {
                   throw new IllegalArgumentException
                   ("email cannot be null");
               }
               try {
 return userRepository.findByEmail(email);               } catch (EmptyResultDataAccessException notFound) {
                  return null;
               }
           }
           @Override
           @Transactional(readOnly = true)
           public List<CalendarUser> findUsersByEmail(final String email) {
               if (email == null) {
                  throw new IllegalArgumentException("email 
                  cannot be null");
               }
               if ("".equals(email)) {
                   throw new IllegalArgumentException("email 
                   cannot be empty string");
               } return userRepository.findAll();         }
           @Override
           public int createUser(final CalendarUser userToAdd) {
               if (userToAdd == null) {
                   throw new IllegalArgumentException("userToAdd 
                   cannot be null");
               }
               if (userToAdd.getId() != null) {
                   throw new IllegalArgumentException("userToAdd.getId() 
                   must be null when creating a "+
                   CalendarUser.class.getName());
               }
 Set<Role> roles = new HashSet<>(); roles.add(roleRepository.findOne(0)); userToAdd.setRoles(roles); CalendarUser result = userRepository.save(userToAdd); userRepository.flush();              return result.getId();
           }
        }
```

正如您在前面的代码中所看到的，使用 JPA 所需的更新片段要比使用 JDBC 所需的代码少得多。这意味着我们可以专注于业务逻辑，而不必担心管道问题。

1.  接下来，我们继续重构`JdbcEventDao.java`文件。首先，我们可以将文件重命名为`JpaEventDao.java`，以表示此文件使用 JPA，而不是标准的 JDBC，如下所示：

```java
//com/packtpub/springsecurity/dataaccess/JpaEventDao.java

package com.packtpub.springsecurity.dataaccess;
... omitted for brevity ...
@Repository
public class JpaEventDao implements EventDao {
 private EventRepository repository;   @Autowired
 public JpaEventDao(EventRepository repository) { if (repository == null) { throw new IllegalArgumentException("repository 
           cannot be null"); } this.repository = repository; }   @Override
   @Transactional(readOnly = true)
   public Event getEvent(int eventId) {
 return repository.findOne(eventId);   }
   @Override
   public int createEvent(final Event event) {
       if (event == null) {
           throw new IllegalArgumentException("event cannot be null");
      }
       if (event.getId() != null) {
           throw new IllegalArgumentException
           ("event.getId() must be null when creating a new Message");
       }
       final CalendarUser owner = event.getOwner();
        if (owner == null) {
           throw new IllegalArgumentException("event.getOwner() 
           cannot be null");
       }
       final CalendarUser attendee = event.getAttendee();
       if (attendee == null) {
           throw new IllegalArgumentException("attendee.getOwner() 
           cannot be null");
       }
       final Calendar when = event.getWhen();
       if(when == null) {
           throw new IllegalArgumentException
           ("event.getWhen()cannot be null");
       }
 Event newEvent = repository.save(event);       return newEvent.getId();
   }
      @Override
   @Transactional(readOnly = true)
   public List<Event> findForUser(final int userId) {
 Event example = new Event(); CalendarUser cu = new CalendarUser(); cu.setId(userId); example.setOwner(cu); return repository.findAll(Example.of(example));   }
     @Override
   @Transactional(readOnly = true)
   public List<Event> getEvents() {
 return repository.findAll();   }
}
```

在前面的代码中，使用 JPA 存储库的更新片段已加粗，因此现在`Event`和`CalendarUser`对象被映射到我们的底层 RDBMS。

此时应用程序无法工作，但仍然可以认为这是一个标记点，在我们继续转换的下一步之前。

在此阶段，你的源代码应该与`chapter05.03-calendar`相同。

# 应用服务

剩下要做的唯一事情是配置 Spring Security 以使用新的工件。

我们需要编辑`DefaultCalendarService.java`文件，并只删除用于向新创建的`User`对象添加`USER_ROLE`的剩余代码，如下所示：

```java
    //com/packtpub/springsecurity/service/DefaultCalendarService.java

    package com.packtpub.springsecurity.service;
    ... omitted for brevity ...
    @Repository
    public class DefaultCalendarService implements CalendarService {
       @Override
       public int createUser(CalendarUser user) {
           String encodedPassword = passwordEncoder.encode(user.getPassword());
           user.setPassword(encodedPassword);
           int userId = userDao.createUser(user);   
 //jdbcOperations.update("insert into         
           calendar_user_authorities(calendar_user,authority) 
           values (?,?)", userId, //"ROLE_USER");           return userId;
       }
    }
```

# 用户详细信息服务对象

让我们来看看以下步骤，以添加`UserDetailsService`对象：

1.  现在，我们需要添加一个新的`UserDetailsService`对象的实现，我们将使用我们的`CalendarUserRepository`接口再次对用户进行身份验证和授权，使用相同的底层 RDBMS，但使用我们新的 JPA 实现，如下所示：

```java
        //com/packtpub/springsecurity/service/UserDetailsServiceImpl.java

        package com.packtpub.springsecurity.service;
        ... omitted for brevity ...
        @Service
        public class UserDetailsServiceImpl
             implements UserDetailsService {
 @Autowired private CalendarUserRepository userRepository; @Override @Transactional(readOnly = true) public UserDetails loadUserByUsername(final String username)           throws UsernameNotFoundException {            CalendarUser user = userRepository.findByEmail(username);
           Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
 for (Role role : user.getRoles()){ grantedAuthorities.add(new SimpleGrantedAuthority
               (role.getName())); } return new org.springframework.security.core.userdetails.User( user.getEmail(), user.getPassword(), grantedAuthorities); }        }

```

1.  现在，我们需要配置 Spring Security 以使用我们自定义的`UserDetailsService`对象，如下所示：

```java
       //com/packtpub/springsecurity/configuration/SecurityConfig.java

        package com.packtpub.springsecurity.configuration;
        ... omitted for brevity ...
        @Configuration
        @EnableWebSecurity
        public class SecurityConfig extends WebSecurityConfigurerAdapter {\
 @Autowired private UserDetailsService userDetailsService;           @Override
          public void configure(AuthenticationManagerBuilder auth) 
          throws Exception {
          auth
 .userDetailsService(userDetailsService)           .passwordEncoder(passwordEncoder());
           }
 @Bean @Override public UserDetailsService userDetailsService() { return new UserDetailsServiceImpl(); }           ...
        }
```

1.  启动应用程序并尝试登录应用程序。现在任何配置的用户都可以登录并创建新事件。您还可以创建新用户，并能够立即以新用户身份登录。

您的代码现在应该看起来像`calendar05.04-calendar`。

# 从关系型数据库（RDBMS）重构为文档数据库

幸运的是，有了 Spring Data 项目，一旦我们有了 Spring Data 实现，大部分困难的工作已经完成。现在，只需要进行一些实现特定的重构更改。

# 使用 MongoDB 的文档数据库实现

我们现在将着手将我们的 RDBMS 实现（使用 JPA 作为我们的 ORM 提供者）重构为使用 MongoDB 作为底层数据库提供者的文档数据库实现。MongoDB（来自 humongous）是一个免费且开源的跨平台面向文档的数据库程序。它被归类为一个 NoSQL 数据库程序，MongoDB 使用类似 JSON 的文档和模式。MongoDB 由 MongoDB Inc.开发，位于[`github.com/mongodb/mongo`](https://github.com/mongodb/mongo)。

# 更新我们的依赖项

我们已经包含了本章所需的所有依赖项，所以您不需要对`build.gradle`文件进行任何更新。然而，如果您只是将 Spring Data JPA 支持添加到您自己的应用程序中，您需要在`build.gradle`文件中添加`spring-boot-starter-data-jpa`作为依赖项，如下所示：

```java
    //build.gradle
    // JPA / ORM / Hibernate:
    //compile('org.springframework.boot:spring-boot-starter-data-jpa')
    // H2 RDBMS
    //runtime('com.h2database:h2')
    // MongoDB:

 compile('org.springframework.boot:spring-boot-starter-data-mongodb') compile('de.flapdoodle.embed:de.flapdoodle.embed.mongo')
```

请注意，我们已经移除了`spring-boot-starter-jpa`依赖。`spring-boot-starter-data-mongodb`依赖将包含所有需要将我们的领域对象连接到我们的嵌入式 MongoDB 数据库的依赖项，同时使用 Spring 和 MongoDB 注解的混合。

我们还添加了**Flapdoodle**嵌入式 MongoDB 数据库，但这只适用于测试和演示目的。嵌入式 MongoDB 将为单元测试提供一个跨平台的 MongoDB 运行平台。这个嵌入式数据库位于[`github.com/flapdoodle-oss/de.flapdoodle.embed.mongo`](https://github.com/flapdoodle-oss/de.flapdoodle.embed.mongo)。

# 在 MongoDB 中重新配置数据库配置

首先，我们将开始转换当前的 JBCP 日历项目。让我们先重新配置数据库以使用 Flapdoodle 嵌入式 MongoDB 数据库。之前，当我们更新这个项目的依赖时，我们添加了一个 Flapdoodle 依赖项，该项目得到了一个嵌入式 MongoDB 数据库，我们可以自动使用它，而不是安装 MongoDB 的完整版本。为了与 JBCP 应用程序保持一致，我们需要更改我们数据库的名称。使用 Spring Data，我们可以使用 YAML 配置来更改 MongoDB 配置，如下所示：

```java
    //src/main/resources/application.yml

    spring
    # MongoDB
 data: mongodb:         host: localhost
 database: dataSource
```

对于我们当前需求最重要的配置是更改数据库名称为`dataSource`，这个名称与本书中我们一直在使用的名称相同。

# 初始化 MongoDB 数据库

使用 JPA 实现时，我们使用了`data.sql`文件来初始化数据库中的数据。对于 MongoDB 实现，我们可以删除`data.sql`文件，并用我们称之为`MongoDataInitializer.java`的 Java 配置文件来替代它：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    MongoDataInitializer.java

    ¦
    @Configuration
    public class MongoDataInitializer {
       @Autowired
       private RoleRepository roleRepository;
       @Autowired
       private CalendarUserRepository calendarUserRepository;
       @Autowired
       private EventRepository eventRepository;
 @PostConstruct       public void setUp() {
 calendarUserRepository.deleteAll(); roleRepository.deleteAll(); eventRepository.deleteAll(); seedRoles(); seedCalendarUsers(); seedEvents();       }
       CalendarUser user1, admin, user2;
       {
 user1 = new CalendarUser(0, "user1@example.com",
           "$2a$04$qr7RWyqOnWWC1nwotUW1nOe1RD5.mKJVHK16WZy6v49pymu1WDHmi",
           "User","1"); admin = new   CalendarUser(1,"admin1@example.com",
           "$2a$04$0CF/Gsquxlel3fWq5Ic/ZOGDCaXbMfXYiXsviTNMQofWRXhvJH3IK",
           "Admin","1"); user2 = new CalendarUser(2,"user2@example.com",
           "$2a$04$PiVhNPAxunf0Q4IMbVeNIuH4M4ecySWHihyrclxW..PLArjLbg8CC",
           "User2","2");       }
       Role user_role, admin_role;
       private void seedRoles(){
           user_role = new Role(0, "ROLE_USER");
           admin_role = new Role(1, "ROLE_ADMIN");
           user_role = roleRepository.save(user_role);
           admin_role = roleRepository.save(admin_role);
       }
       private void seedEvents(){
 // Event 1           Event event1 = new Event(100, "Birthday Party", "This is 
           going to be a great birthday", new 
           GregorianCalendar(2017,6,3,6,36,00), user, admin);
 // Event 2           Event event2 = new Event(101, "Conference Call", 
           "Call with the client",new 
           GregorianCalendar(2017,11,23,13,00,00),user2, user);
 // Event 3           Event event3 = new Event(102, "Vacation",
           "Paragliding in Greece",new GregorianCalendar(2017,8,14,11,30,00),
           admin, user2);
           // Save Events
 eventRepository.save(event1); eventRepository.save(event2); eventRepository.save(event3);       }
       private void seedCalendarUsers(){
           // user1
           user1.addRole(user_role);
          // admin2
           admin.addRole(user_role);
           admin.addRole(admin_role);
           // user2
           user2.addRole(user_role);
 calendarUserRepository.save(user1); calendarUserRepository.save(admin); calendarUserRepository.save(user2);       }
    }
```

这将在加载时执行，并将将相同的数据种子到我们的 MongoDB 中，就像我们使用我们的 H2 数据库一样。

# 使用 MongoDB 映射领域对象

首先，让我们将我们的`Event.java`文件映射到领域对象，以便将每个领域对象保存为我们的 MongoDB 数据库中的文档。这可以通过执行以下步骤来实现：

1.  在文档数据库中，领域对象映射有所不同，但相同的 ORM 概念仍然适用。让我们从 Event JPA 实现开始，然后看看如何将我们的`Entity`转换为文档映射：

```java
        //src/main/java/com/packtpub/springsecurity/domain/Event.java

         ...
 import javax.persistence.*; @Entity @Table(name = "events")        public class Event implements Serializable{
 @Id @GeneratedValue(strategy = GenerationType.AUTO)           private Integer id;
           private String summary;
           private String description;
           private Calendar when;
 @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="owner", referencedColumnName="id")           private CalendarUser owner;
 @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name="attendee", referencedColumnName="id")           private CalendarUser attendee;
           ¦
```

1.  在基于实体的 JPA 映射中，我们需要使用六个不同的注解来创建所需的映射。现在，在基于文档的 MongoDB 映射中，我们需要更改所有的先前映射注解。下面是我们完全重构的`Event.java`文件的示例：

```java
        //src/main/java/com/packtpub/springsecurity/domain/Event.java

 import org.springframework.data.annotation.Id; import org.springframework.data.annotation.PersistenceConstructor; import org.springframework.data.domain.Persistable; import org.springframework.data.mongodb.core.mapping.DBRef; import org.springframework.data.mongodb.core.mapping.Document;        ...
 @Document(collection="events")        public class Event implements Persistable<Integer>, Serializable{
 @Id             private Integer id;
             private String summary;
             private String description;
             private Calendar when;
 @DBRef           private CalendarUser owner;
 @DBRef           private CalendarUser attendee;
 @PersistenceConstructor           public Event(Integer id,
                 String summary,
                 String description,
                 Calendar when,
                 CalendarUser owner,
                 CalendarUser attendee) {
                  ...
          }
```

在上述代码中，我们可以看到一些值得注意的更改：

1.  首先，我们需要声明类为`@o.s.d.mongodb.core.mapping.Document`类型，并为这些文档提供集合名称。

1.  接下来，`Event`类必须实现`o.s.d.domain.Persistable`接口，为我们的文档提供主键类型（`Integer`）。

1.  现在，我们将我们的领域 ID 注解更改为`@o.s.d.annotation.Id`，以定义领域主键。

1.  之前，我们必须将我们的所有者和参与者`CalendarUser`对象映射到两个不同的映射注解。

1.  现在，我们只需要定义两种类型为`@o.s.d.mongodb.core.mapping.DBRef`，并允许 Spring Data 处理底层引用。

1.  我们必须添加的最后一个注解定义了一个特定的构造函数，用于将新文档添加到我们的文档中，通过使用`@o.s.d.annotation.PersistenceConstructor`注解。

1.  现在我们已经回顾了从 JPA 转换到 MongoDB 所需的更改，让我们从`Role.java`文件开始转换另一个领域对象：

```java
        //src/main/java/com/packtpub/springsecurity/domain/Role.java

        ...
        import org.springframework.data.annotation.Id;
        import org.springframework.data.annotation.PersistenceConstructor;
        import org.springframework.data.domain.Persistable;
        import org.springframework.data.mongodb.core.mapping.Document;
 @Document(collection="role")        public class Role implements Persistable<Integer>, Serializable {
 @Id            private Integer id;
            private String name;
            public Role(){}
 @PersistenceConstructor        public Role(Integer id, String name) {
            this.id = id;
            this.name = name;
         }
```

1.  我们需要重构的最后一个领域对象是我们的`CalendarUser.java`文件。毕竟，这是这个应用程序中最复杂的领域对象：

```java
        //src/main/java/com/packtpub/springsecurity/domain/CalendarUser.java

        ...
        import org.springframework.data.annotation.Id;
        import org.springframework.data.annotation.PersistenceConstructor;
        import org.springframework.data.domain.Persistable;
        import org.springframework.data.mongodb.core.mapping.DBRef;
        import org.springframework.data.mongodb.core.mapping.Document;
 @Document(collection="calendar_users")        public class CalendarUser implements Persistable<Integer>, 
        Serializable {
 @Id           private Integer id;
           private String firstName;
           private String lastName;
           private String email;
           private String password;
 @DBRef(lazy = false)          private Set<Role> roles = new HashSet<>(5);
          public CalendarUser() {}
 @PersistenceConstructor          public CalendarUser(Integer id,String email, String password,
          String firstName,String lastName) {
             this.id = id;
             this.firstName = firstName;
             this.lastName = lastName;
             this.email = email;
             this.password = password;
           }
```

正如你所见，将我们的领域对象从 JPA 重构为 MongoDB 的努力相当简单，并且比 JPA 配置需要的注解配置要少。

# Spring Data 对 MongoDB 的仓库

现在我们只需要对从 JPA 实现到 MongoDB 实现进行少量更改即可重构。我们将从重构我们的`CalendarUserRepository.java`文件开始，通过更改我们仓库所扩展的接口，如下所示：

```java
    //com/packtpub/springsecurity/repository/CalendarUserRepository.java

    ...
 import org.springframework.data.mongodb.repository.MongoRepository;    public interface CalendarUserRepository extends MongoRepository
    <CalendarUser, Integer> {
       ...
```

这个相同的更改需要应用到`EventRepository.java`文件和`RoleRepository.java`文件上。

如果你需要帮助进行这些更改，请记住`chapter05.05`的源代码将有完整的代码供您参考。

# MongoDB 中的数据访问对象

在我们的`EventDao`接口中，我们需要创建一个新的`Event`对象。使用 JPA，我们的对象 ID 可以自动生成。使用 MongoDB，有几种方式可以分配主键标识符，但为了这个演示，我们只需使用原子计数器，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/dataaccess/MongoEventDao.java

    ...
 import java.util.concurrent.atomic.AtomicInteger;    @Repository
    public class MongoEventDao implements EventDao {
      // Simple Primary Key Generator
 private AtomicInteger eventPK = new AtomicInteger(102);       ...
       @Override
       public int createEvent(Event event) {
           ...
           // Get the next PK instance
 event.setId(eventPK.incrementAndGet()); Event newEvent = repository.save(event);           return newEvent.getId();
       }
       ...
```

从技术上讲，我们的`CalendarUserDao`对象没有变化，但为了本书的一致性，我们将实现文件的名称更改为表示使用`Mongo`：

```java
    @Repository
    public class MongoCalendarUserDao implements CalendarUserDao {
```

对于这个重构示例，没有其他**数据访问对象**（**DAO**）的更改需求。

启动应用程序，它将像以前一样运行。尝试以`user1`和`admin1`的身份登录，并测试以确保两个用户都可以向系统添加新事件，以确保整个应用程序的映射正确。

你应该从`chapter05.05-calendar`的源代码开始。

# 总结

我们已经探讨了 Spring Data 项目的强大和灵活性，以及与应用程序开发相关的几个方面，还包括了与 Spring Security 的集成。在本章中，我们覆盖了 Spring Data 项目及其部分功能。我们还看到了从使用 SQL 的遗留 JDBC 代码到使用 JPA 的 ORM，以及从使用 Spring Data 的 JPA 实现到使用 Spring Data 的 MongoDB 实现的重构过程。我们还覆盖了配置 Spring Security 以利用关系数据库中的 ORM `Entity`和文档数据库中的配置。

在下一章中，我们将探讨 Spring Security 对基于 LDAP 的认证的内置支持。


# 第六章：LDAP 目录服务

在本章中，我们将回顾**轻量级目录访问协议**（**LDAP**）并学习如何将其集成到 Spring Security 启用的应用程序中，为感兴趣的各方提供认证、授权和用户信息服务。

在本章中，我们将介绍以下主题：

+   学习与 LDAP 协议和服务器实现相关的一些基本概念

+   在 Spring Security 中配置自包含 LDAP 服务器

+   启用 LDAP 认证和授权

+   理解 LDAP 搜索和用户匹配背后的模型

+   从标准 LDAP 结构中检索额外的用户详细信息

+   区分 LDAP 认证方法并评估每种类型的优缺点

+   显式使用**Spring bean**声明配置 Spring Security LDAP

+   连接到外部 LDAP 目录

+   探索对 Microsoft AD 的内置支持

+   我们还将探讨如何在处理自定义 AD 部署时为 Spring Security 定制更多灵活性

# 理解 LDAP

LDAP 起源于 30 多年前的概念性目录模型-类似于组织结构图和电话簿的结合。如今，LDAP 越来越多地被用作集中企业用户信息、将成千上万的用户划分为逻辑组以及在不同系统之间统一共享用户信息的方法。

出于安全考虑，LDAP 常被用于实现集中化的用户名和密码验证-用户的凭据存储在 LDAP 目录中，代表用户对目录进行认证请求。这使得管理员的管理工作得到简化，因为用户凭据-登录 ID、密码及其他详细信息-都存储在 LDAP 目录的单一位置中。此外，诸如组织结构、团队分配、地理位置和企业层级等信息，都是基于用户在目录中的位置来定义的。

# LDAP

到目前为止，如果你以前从未使用过 LDAP，你可能会想知道它是什么。我们将通过 Apache Directory Server 2.0.0-M231.5 示例目录中的屏幕截图来展示一个 LDAP 架构示例，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/22d17476-4f8f-400b-b906-1e884b164aaa.png)

从特定用户条目`uid=admin1@example.com`（在前面的屏幕截图中突出显示）开始，我们可以通过在这个树节点开始并向上升级来推断`admin1`的组织成员资格。我们可以看到用户`aeinstein`是组织单位（`ou=users`）的成员，而这个单位本身是域`example.com`的一部分（在前面的屏幕截图中显示的缩写`dc`代表域组件）。在这个之前是 LDAP 树本身的组织元素（`DIT`和`Root DSE`），这在 Spring Security 的上下文中与我们无关。用户`aeinstein`在 LDAP 层次结构中的位置在语义上和定义上都是有意义的-你可以想象一个更复杂的层次结构，轻松地说明一个大型组织的组织和部门界限。

沿着树向下走到一个单独的叶节点形成的从上到下的完整路径是由沿途的所有中间节点组成的一个字符串，就像`admin1`的节点路径一样，如下所示：

```java
    uid=admin1,ou=users,dc=example,dc=com
```

前面的节点路径是唯一的，被称为节点的** Distinguished Name** (**DN**)。Distinguished Name 类似于数据库的主键，允许在复杂的树结构中唯一标识和定位一个节点。在 Spring Security LDAP 集成中，我们将看到节点的 DN 在认证和搜索过程中被广泛使用。

请注意，在与`admin1`相同组织级别的列表中还有几个其他用户。所有这些用户都被假设为与`admin1`处于相同的组织位置。尽管这个例子中的组织结构相对简单和平坦，但 LDAP 的结构是任意灵活的，可能有多个嵌套层次和逻辑组织。

Spring Security LDAP 支持由 Spring LDAP 模块提供([`www.springsource.org/ldap`](http://www.springsource.org/ldap))，该模块实际上是从 Spring 框架核心和 Spring Security 项目分离出来的一个独立项目。它被认为是稳定的，并提供了一组有助于包装标准 Java LDAP 功能的封装器。

# 常见的 LDAP 属性名称

树中的每个实际条目都是由一个或多个对象类定义的。对象类是组织的一个逻辑单位，将一组语义上相关的属性组合在一起。通过将树中的条目声明为特定对象类的一个实例，如一个人，LDAP 目录的组织者就能够向目录的用户提供一个清晰的指示，表明目录中的每个元素代表什么。

LDAP 有一套丰富的标准模式，涵盖可用的 LDAP 对象类及其适用的属性（以及其他大量信息）。如果您计划进行广泛的 LDAP 工作，强烈建议您查阅一本好的参考指南，例如书籍《Zytrax OpenLDAP》的附录（[`www.zytrax.com/books/ldap/ape/`](http://www.zytrax.com/books/ldap/ape/)），或《Internet2 Consortium 的与人员相关的模式指南》([`middleware.internet2.edu/eduperson/`](http://middleware.internet2.edu/eduperson/))。

在前一部分中，我们了解到 LDAP 树中的每个条目都有一个 DN，它唯一地标识树中的条目。DN 由一系列属性组成，其中一个（或更多）用于唯一标识表示 DN 的条目向下走的路径。由于 DN 描述的路径的每个段代表一个 LDAP 属性，你可以参考可用的、定义良好的 LDAP 模式和对象类，以确定任何给定 DN 中的每个属性的含义。

我们在下面的表格中包含了一些常见属性和它们的意义。这些属性通常是组织属性——意思是它们通常用于定义 LDAP 树的组织结构——并且按从上到下的顺序排列在你可能在典型 LDAP 安装中看到的结构：

| **属性名称** | **描述** | **示例** |
| --- | --- | --- |
| `dc` | **域组件**：通常是 LDAP 层次结构中的最高级别组织。 | `dc=jbcpcalendar,dc=com` |
| `c` | **国家**：一些 LDAP 层次结构按国家进行高层次的结构化。 | `c=US` |
| `o` | **组织名称**：这是一个用于分类 LDAP 资源的父级商业组织。 | `o=Oracle Corporation` |
| `ou` | **组织单位**：这是一个通常在组织内的分部商业组织。 | `ou=Product Development` |
| `cn` | **通用名称**：这是对象的共同名称，或唯一名称或人类可读名称。对于人类，这通常是人的全名，而对于 LDAP 中的其他资源（如计算机等），它通常是主机名。 | `cn=Super Visor``cn=Jim Bob` |
| `uid` | **用户 ID**：尽管不是组织性质的，但`uid`属性通常是 Spring 在用户认证和搜索时查找的。 | `uid=svisor` |
| `userPassword` | **用户密码**：此属性存储与该属性关联的`person`对象的密码。它通常是使用`SHA`或其他类似方法进行单向散列的。 | `userPassword=plaintext``userPassword={SHA}cryptval` |

然而，前表中的属性通常是的目录树的组织属性，因此，它们可能形成各种搜索表达式或映射，以便配置 Spring Security 与 LDAP 服务器进行交互。

记住，有数百个标准的 LDAP 属性-这些只是你在与一个完全填充的 LDAP 服务器集成时可能会看到的很小的一部分。

# 更新我们的依赖项

我们已经为您本章所需的所有依赖项，所以你不需要对你的`build.gradle`文件做任何更新。然而，如果你只是想为你的应用程序添加 LDAP 支持，你需要在`build.gradle`中添加`spring-security-ldap`作为依赖项，如下所示：

```java
    //build.gradle

    dependencies {
    // LDAP:
    compile('org.springframework.boot:spring-boot-starter-data-ldap')
    compile("org.springframework.ldap:spring-ldap-core")
    compile("org.springframework.security:spring-security-ldap")
 compile("org.springframework:spring-tx")    compile("com.unboundid:unboundid-ldapsdk")
       ...
    }
```

由于 Gradle 的一个艺术品解析问题，`spring-tx`必须被引入，否则 Gradle 会获取一个较旧的版本，无法使用。

如前所述，Spring Security 的 LDAP 支持是建立在 Spring LDAP 之上的。Gradle 会自动将这些依赖作为传递依赖引入，因此无需明确列出。

如果你在你的网络应用程序中使用**ApacheDS**运行 LDAP 服务器，正如我们在我们的日历应用程序中所做的那样，你需要添加 ApacheDS 相关的 JAR 包依赖。由于这些更新已经被包含在我们的示例应用程序中，所以无需对示例应用程序进行这些更新。请注意，如果你连接到一个外部的 LDAP 服务器，这些依赖是不必要的：

```java
//build.gradle

    compile 'org.apache.directory.server:apacheds-core:2.0.0-M23'
    compile 'org.apache.directory.server:apacheds-protocol-ldap:2.0.0-M23'
    compile 'org.apache.directory.server:apacheds-protocol-shared:2.0.0
    -M23'
```

配置嵌入式 LDAP 集成

现在让我们启用基于 LDAP 的 JBCP 日历应用程序认证。幸运的是，这是一个相对简单的练习，使用嵌入式 LDAP 服务器和一个示例 LDIF 文件。在这个练习中，我们将使用为这本书创建的 LDIF 文件，旨在捕获许多与 LDAP 和 Spring Security 相关的常见配置场景。我们还包含了一些其他示例 LDIF 文件，其中一些来自 Apache DS 2.0.0-M23，还有一个来自 Spring Security 单元测试，你可以选择实验它们。

# 配置 LDAP 服务器引用

第一步是配置嵌入式 LDAP 服务器。Spring Boot 会自动配置一个嵌入式 LDAP 服务器，但我们还需要稍微调整一下配置。对你的`application.yml`文件进行以下更新：

```java
      //src/main/resources/application.yml

      spring:
      ## LDAP
 ldap: embedded: 
```

```java
 ldif: classpath:/ldif/calendar.ldif base-dn: dc=jbcpcalendar,dc=com port: 33389
```

你应该从`chapter06.00-calendar`的源代码开始。

我们从`classpath`加载`calendar.ldif`文件，并使用它来填充 LDAP 服务器。`root`属性使用指定的 DN 声明 LDAP 目录的根。这应该与我们在使用的 LDIF 文件中的逻辑根 DN 相对应。

请注意，对于嵌入式 LDAP 服务器，`base-dn`属性是必需的。如果没有指定或指定不正确，你可能会在 Apache DS 服务器的初始化过程中收到几个奇怪的错误。还要注意，`ldif`资源应该只加载一个`ldif`，否则服务器将无法启动。Spring Security 要求一个资源，因为使用诸如`classpath*:calendar.ldif`的东西不能提供所需要的确切排序。

我们将在 Spring Security 配置文件中重新使用这里定义的 bean ID，当我们声明 LDAP 用户服务和其他配置元素时。在使用内置 LDAP 模式时，`<ldap-server>`声明上的所有其他属性都是可选的。

# 启用 LDAP AuthenticationProviderNext 接口

接下来，我们需要配置另一个`AuthenticationProvider`接口，以将用户凭据与 LDAP 提供者进行核对。只需更新 Spring Security 配置，使用`o.s.s.ldap.authentication.LdapAuthenticationProvider`引用，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
 .ldapAuthentication() .userSearchBase("") .userSearchFilter("(uid={0})") .groupSearchBase("ou=Groups") .groupSearchFilter("(uniqueMember={0})") .contextSource(contextSource()) .passwordCompare() .passwordAttribute("userPassword");    }
    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
 return new DefaultSpringSecurityContextSource( Arrays.asList("ldap://localhost:33389/"), "dc=jbcpcalendar,dc=com");
    }
```

我们稍后会讨论这些属性。现在，先让应用程序恢复正常运行，然后尝试使用`admin1@example.com`作为用户名和`admin1`作为密码登录。你应该可以登录！

您的源代码应该看起来像`chapter05.01-calendar`。

# 调试内置 LDAP

你很可能会遇到嵌入式 LDAP 的难以调试的问题。Apache DS 通常对其错误信息不太友好，在 Spring Security 嵌入式模式下更是如此。如果你在尝试通过浏览器访问应用程序时遇到`404`错误，有很大可能性是没有正确启动。如果你无法运行这个简单示例，需要检查以下几点：

+   确保在您的`configuration`文件中的`DefaultSpringSecurityContextSource`声明上设置了`baseDn`属性，并确保它与在启动时加载的 LDIF 文件中定义的根匹配。如果您遇到引用缺失分区错误，很可能是漏掉了`root`属性或与您的 LDIF 文件不匹配。

+   请注意，嵌入式 LDAP 服务器启动失败并不是致命失败。为了诊断加载 LDIF 文件时的错误，您需要确保适当的日志设置，包括 Apache DS 服务器的日志记录，至少在错误级别启用。LDIF 加载器位于`org.apache.directory.server.protocol.shared.store`包下，应使用此包来启用 LDIF 加载错误的日志记录。

+   如果应用服务器非正常关闭，你可能需要删除临时目录（Windows 系统中的`%TEMP%`或 Linux 系统中的`/tmp`）中的某些文件，以便再次启动服务器。关于这方面的错误信息（幸运的是）相当清晰。不幸的是，内置的 LDAP 不如内置的 H2 数据库那么无缝且易于使用，但它仍然比尝试下载和配置许多免费的外部 LDAP 服务器要容易得多。

一个出色的工具，用于调试或访问一般 LDAP 服务器的是 Apache Directory Studio 项目，该项目提供独立版本和 Eclipse 插件版本。免费下载可在[`directory.apache. Org/studio/`](http://directory.apache.org/studio/)找到。如果你想跟随本书，现在可能想下载 Apache Directory Studio 2.0.0-M23。

# 了解 Spring LDAP 认证如何工作

我们看到我们能够使用在 LDAP 目录中定义的用户登录。但是，当用户发出登录请求时，在 LDAP 中实际上会发生什么？LDAP 认证过程有三个基本步骤：

1.  将用户提供的凭据与 LDAP 目录进行认证。

1.  基于用户在 LDAP 中的信息，确定其`GrantedAuthority`对象。

1.  从 LDAP 条目预加载用户信息到一个自定义的`UserDetails`对象中，供应用程序进一步使用。

# 验证用户凭据

对于第一步，即对 LDAP 目录进行认证，一个自定义认证提供者被连接到`AuthenticationManager`。`o.s.s.ldap.authentication.LdapAuthenticationProvider`接口接受用户提供的凭据，并将它们与 LDAP 目录进行验证，如下面的图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f9e599ad-73a4-479a-98d9-1495d84b87d9.png)

我们可以看到`o.s.s.ldap.authentication.LdapAuthenticator`接口定义了一个委派，以允许提供者以可定制的方式提出认证请求。我们到目前为止隐式配置的实现，`o.s.s.ldap.authentication.BindAuthenticator`，尝试使用用户的凭据以登录到 LDAP 服务器，好像是用户自己建立连接一样。对于内嵌服务器，这对于我们的认证需求是充分的；然而，外部 LDAP 服务器可能更严格，在这些服务器上，用户可能不允许绑定到 LDAP 目录。幸运的是，存在一种替代的认证方法，我们将在本章后面探索。

如前图所示，请注意，搜索是在由`DefaultSpringSecurityContextSource`参考的`baseDn`属性创建的 LDAP 上下文中执行的。对于内嵌服务器，我们不使用这些信息，但对于外部服务器参考，除非提供`baseDn`，否则会使用匿名绑定。对于需要有效凭据才能搜索 LDAP 目录的组织来说，保留对目录中信息公共可用的某些控制是非常常见的，因此，在现实世界场景中`baseDn`几乎总是必需的。`baseDn`属性代表具有对目录进行绑定并执行搜索的有效访问权限的用户的全 DN。

# 使用 Apache Directory Studio 演示认证过程

我们将通过使用 Apache Directory Studio 1.5 连接到我们的内嵌 LDAP 实例并执行 Spring Security 正在执行的相同步骤来演示认证过程是如何工作的。在整个模拟中我们将使用`user1@example.com`。这些步骤将有助于确保对幕后发生的事情有坚实的基础，并有助于在您遇到难以确定正确配置的情况下提供帮助。

确保日历应用程序已经启动并运行。接下来，启动 Apache Directory Studio 1.5 并关闭欢迎屏幕。

# 匿名绑定到 LDAP

第一步是以匿名方式绑定到 LDAP。由于我们没有在`DefaultSpringSecurityContextSource`对象上指定`baseDn`和`password`属性，因此绑定是匿名的。在 Apache Directory Studio 中，使用以下步骤创建一个连接：

1.  点击文件 | 新建 | LDAP 浏览器 | LDAP 连接。

1.  点击下一步。

1.  输入以下信息，然后点击下一步：

    +   连接名称：`calendar-anonymous`

    +   主机名：`localhost`

    +   端口：``33389``

1.  我们没有指定`baseDn`，因此选择无认证作为认证方法。

1.  点击完成。

您可以安全地忽略指示没有默认架构信息的存在的消息。现在您应该可以看到，您已经连接到了内嵌的 LDAP 实例。

# 搜索用户

现在我们已经有了一个连接，我们可以使用它来查找我们希望绑定的用户的 DN，通过执行以下步骤：

1.  右键点击`DIT`并选择新建 | 新搜索。

1.  输入搜索基础`dc=jbcpcalendar,dc=com`。这对应于我们的`DefaultSpringSecurityContextSource`对象的`baseDn`属性，我们指定的。

1.  输入过滤器`uid=user1@example.com`。这对应于我们为`AuthenticationManagerBuilder`的`userSearchFilter`方法指定的值。注意我们包括了括号，并用`{0}`值替换了我们尝试登录的用户名。

1.  点击搜索。

1.  点击我们搜索返回的单个结果的 DN。现在您可以看到我们的 LDAP 用户被显示出来。注意这个 DN 与我们搜索的值匹配。记住这个 DN，因为它将在我们下一步中使用。

# 以用户身份绑定到 LDAP

现在我们已经找到了我们用户的完整 DN，我们需要尝试以该用户身份绑定到 LDAP 以验证提交的密码。这些步骤与我们已经完成的匿名绑定相同，只是我们将指定我们要认证的用户的凭据。

在 ApacheDS 中，使用以下步骤创建一个连接：

1.  选择文件 | 新建 | LDAP 浏览器 | LDAP 连接。

1.  点击下一步。

1.  输入以下信息，然后点击下一步：

    +   连接名称：`calendar-user1`

    +   主机名：`localhost`

    +   端口：`33389`

1.  将认证方法保留为简单认证。

1.  从我们的搜索结果中输入 DN 作为`Bind DN`。值应该是`uid=admin1@example.com,ou=Users,dc=jbcpcalendar,dc=com`。

1.  `Bind`密码应该是登录时提交的用户密码。在我们这个案例中，我们希望使用`admin1`来进行成功的认证。如果输入了错误的密码，我们将无法连接，Spring Security 会报告一个错误。

1.  点击完成。

当 Spring Security 能够成功绑定提供的用户名和密码时，它会确定这个用户的用户名和密码是正确的（这类似于我们能够创建一个连接）。Spring Security 然后将继续确定用户的角色成员资格。

# 确定用户角色成员资格

在用户成功对 LDAP 服务器进行身份验证后，下一步必须确定授权信息。授权是由主体的角色列表定义的，LDAP 身份验证用户的角色成员资格是根据以下图表所示确定的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/53744a8e-629c-4e8f-919d-a6b1ff0cac4e.png)

我们可以看到，在用户对 LDAP 进行身份验证后，`LdapAuthenticationProvider`委托给`LdapAuthoritiesPopulator`。`DefaultLdapAuthoritiesPopulator`接口将尝试在 LDAP 层次结构的另一个条目或其下查找已验证用户的 DN。在用户角色分配的位置搜索的 DN 定义在`groupSearchBase`方法中；在我们的示例中，我们将此设置为`groupSearchBase("ou=Groups")`。当用户的 DN 位于`groupSearchBase` DN 下方的 LDAP 条目中时，在该条目中找到用户 DN 的属性用于赋予他们角色。

如何将 Spring Security 角色与 LDAP 用户相关联可能会有些令人困惑，所以让我们看看 JBCP 日历 LDAP 存储库，并了解用户与角色关联是如何工作的。`DefaultLdapAuthoritiesPopulator`接口使用`AuthenticationManagerBuilder`声明中的几个方法来管理对用户角色的搜索。这些属性大约按以下顺序使用：

1.  `groupSearchBase`：它定义了 LDAP 集成应该查找用户 DN 的一个或多个匹配项的基础 DN。默认值是从 LDAP 根进行搜索，这可能会很昂贵。

1.  `groupSearchFilter`：它定义了用于匹配用户 DN 到位于`groupSearchBase`下条目的属性的 LDAP 搜索过滤器。这个搜索过滤器有两个参数——第一个（`{0}`）是用户的 DN，第二个（`{1}`）是用户的名字。默认值是`uniqueMember={0}`。

1.  `groupRoleAttribute`：它定义了匹配条目的属性，该属性将用于组成用户的`GrantedAuthority`对象。默认值是`cn`。

1.  `rolePrefix`：它将被添加到在`groupRoleAttribute`中找到的值前面，以构成 Spring Security 的`GrantedAuthority`对象。默认值是`ROLE_`。

这可能有点抽象，对于新开发者来说难以理解，因为它与我们迄今为止在 JDBC 和 JPA 基础上的`UserDetailsService`实现非常不同。让我们继续通过`user1@example.com`用户在 JBCP 日历 LDAP 目录中走一遍登录过程。

# 使用 Apache Directory Studio 确定角色

我们现在将尝试使用 Apache Directory Studio 确定我们的用户角色。使用我们之前创建的`calendar-user1`连接，执行以下步骤：

1.  在`DIT`上右键点击，选择新建 | 新搜索。

1.  输入搜索基础`ou=Groups,dc=jbcpcalendar,dc=com`。这对应于我们为`AuthenticationManagerBuilder`对象指定的`DefaultSpringSecurityContextSource`对象中的`baseDn`属性，加上我们为`AuthenticationManagerBuilder`对象指定的`groupSearchBase`属性。

1.  输入过滤器`uniqueMember=uid=user1@example.com,ou=Users,dc=jbcpcalendar,dc=com`。这对应于默认的`groupSearchFilter`属性（`uniqueMember={0}`）。注意我们已经用我们在上一步骤中找到的用户的全 DN 替换了`{0}`值。

1.  点击搜索。

1.  你会观察到，在我们的搜索结果中只有`User`组返回。点击我们搜索返回的单个结果的 DN。现在你可以在 Apache DS 中看到`User`组。注意该组有一个`uniqueMember`属性，包含了我们的用户和其他用户的全 DN。

现在，Spring Security 会为每个搜索结果创建一个`GrantedAuthority`对象，通过将找到的组的名称强制转换为大写并在组名称前加上`ROLE_`前缀。伪代码看起来类似于以下代码片段：

```java
    foreach group in groups:

    authority = ("ROLE_"+group).upperCase()

    grantedAuthority = new GrantedAuthority(authority)
```

Spring LDAP 和你的灰质一样灵活。请记住，虽然这是一种组织 LDAP 目录以与 Spring Security 兼容的方法，但典型的使用场景正好相反——一个已经存在的 LDAP 目录需要与 Spring Security 进行集成。在许多情况下，你将能够重新配置 Spring Security 以处理 LDAP 服务器的层次结构；然而，关键是你需要有效地规划并理解 Spring 在查询时如何与 LDAP 合作。用你的大脑，规划用户搜索和组搜索，并提出你能想到的最优计划——尽量保持搜索的范围最小和尽可能精确。

你能描述一下我们的`admin1@example.com`用户登录结果会有何不同吗？如果你此刻感到困惑，我们建议你稍作休息，尝试使用 Apache Directory Studio 浏览嵌入式 LDAP 服务器，该服务器通过运行应用程序进行配置。如果你尝试按照之前描述的算法自己搜索目录，那么你可能会更容易掌握 Spring Security 的 LDAP 配置流程。

# 映射 UserDetails 的额外属性

最后，一旦 LDAP 查询为用户分配了一组`GrantedAuthority`对象，`o.s.s.ldap.userdetails.LdapUserDetailsMapper`将咨询`o.s.s.ldap.userdetails.UserDetailsContextMapper`，以检索任何其他详细信息，以填充应用程序使用的`UserDetails`对象。

使用`AuthenticationManagerBuilder`，到目前为止，我们已经配置了`LdapUserDetailsMapper`将用于从 LDAP 目录中用户的条目中获取信息，并填充`UserDetails`对象：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/a8ad64e3-6e2c-4cbf-9413-97afc801dc42.png)

我们马上看到如何配置`UserDetailsContextMapper`从标准的 LDAP `person`和`inetOrgPerson`对象中获取大量信息。带有基础`LdapUserDetailsMapper`，存储的不仅仅是`username`、`password`和`GrantedAuthority`。

尽管在 LDAP 用户认证和详细信息检索的背后涉及更多的机械设备，但你会注意到整个过程似乎与我们在第四章中研究的 JDBC 认证（认证用户并填充`GrantedAuthority`） somewhat similar（有所相似）。与 JDBC 认证一样，可以执行 LDAP 集成的高级配置。让我们深入了解一下有什么可能性！

# 高级 LDAP 配置

一旦我们超越了 LDAP 集成的基础知识，Spring Security LDAP 模块中还有许多其他配置能力，这些能力仍然符合`WebSecurityConfigurerAdapter`风格的配置。这包括检索用户个人信息、用户认证的额外选项以及将 LDAP 用作与标准`DaoAuthenticationProvider`类结合的`UserDetailsService`接口。

# JBCP LDAP 用户示例

我们在 JBCP 日历`LDIF`文件中提供了许多不同的用户。以下快速参考表可能会帮助您进行高级配置练习或自我探索：

| **用户名/密码** | **角色（们）** | **密码编码** |
| --- | --- | --- |
| `admin1@example.com`/`admin1` | `ROLE_ADMIN`, `ROLE_USER` | 纯文本 |
| `user1@example.com`/`user1` | `ROLE_USER` | 纯文本 |
| `shauser@example.com`/`shauser` | `ROLE_USER` | `{sha}` |
| `sshauser@example.com`/`sshauser` | `ROLE_USER` | `{ssha}` |
| `hasphone@example.com`/`hasphone` | `ROLE_USER` | 纯文本（在`telephoneNumber`属性中） |

我们将在下一节解释为什么密码编码很重要。

# 密码对比与绑定认证

某些 LDAP 服务器将被配置为不允许某些个别用户直接绑定到服务器，或者不允许使用匿名绑定（到目前为止我们一直在用于用户搜索的绑定方式）。这在希望限制能够从目录中读取信息的用户集的大型组织中较为常见。

在这些情况下，标准的 Spring Security LDAP 认证策略将不起作用，必须使用替代策略，由`o.s.s.ldap.authentication.PasswordComparisonAuthenticator`实现：

类`BindAuthenticator`）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/0057e6ec-a371-49a8-9148-ad56695d435d.png)

`PasswordComparisonAuthenticator`接口连接到 LDAP，搜索与用户提供的用户名匹配的 DN。然后将用户提供的密码与匹配的 LDAP 条目上的`userPassword`属性进行比较。如果编码的密码匹配，用户将被认证，流程继续，与`BindAuthenticator`类似。

# 配置基本的密码比较

配置密码比较认证而不是绑定认证，只需在`AuthenticationManagerBuilder`声明中添加一个方法即可。更新`SecurityConfig.java`文件，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
       throws Exception {
       auth
         .ldapAuthentication()
         .userSearchBase("")
         .userSearchFilter("(uid={0})")
         .groupSearchBase("ou=Groups")
         .groupSearchFilter("(uniqueMember={0})")
         .contextSource(contextSource())
 .passwordCompare() .passwordEncoder(new LdapShaPasswordEncoder()) .passwordAttribute("userPassword");    }
```

`PasswordCompareConfigurer`类通过声明`passwordCompare`方法来使用，该类使用`PlaintextPasswordEncoder`进行密码编码。要使用`SHA-1`密码算法，我们需要设置一个密码编码器，我们可以使用`o.s.s.a.encoding.LdapShaPasswordEncoder`为`SHA`支持（回想我们在第四章，*基于 JDBC 的认证*中广泛讨论了`SHA-1`密码算法）。

在我们的`calendar.ldif`文件中，我们将`password`字段设置为`userPassword`。`PasswordCompareConfigurer`类的默认`password`属性是`password`。因此，我们还需要使用`passwordAttribute`方法覆盖`password`属性。

在重启服务器后，您可以尝试使用`shauser@example.com`作为`用户名`和`shauser`作为`密码`登录。

您的代码应类似于`chapter06.02-calendar`。

# LDAP 密码编码和存储

LDAP 对多种密码编码算法提供了普遍支持，这些算法从明文到单向散列算法-类似于我们在前一章中探讨的-带有基于数据库的认证。LDAP 密码最常用的存储格式是`SHA`（`SHA-1`单向散列）和`SSHA`（`SHA-1`单向散列加盐值）。许多 LDAP 实现广泛支持的其他密码格式在*RFC 2307*中详细记录，*作为网络信息服务使用的 LDAP 方法*（[`tools.ietf.org/html/rfc2307`](http://tools.ietf.org/html/rfc2307)）。*RFC 2307*的设计者在密码存储方面做了一件非常聪明的事情。保存在目录中的密码当然是用适当的算法（如`SHA`等）进行编码，然后，它们前面加上用于编码密码的算法。这使得 LDAP 服务器很容易支持多种密码编码算法。例如，一个`SHA`编码的密码在目录中以`{SHA}5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8`的形式存储。

我们可以看到，密码存储算法非常清楚地用`{SHA}`标记表示，并与密码一起存储。

`SSHA`记号试图将强大的`SHA-1`散列算法与密码加盐结合起来，以防止字典攻击。正如我们在上一章中回顾的密码加盐一样，在计算散列之前将盐添加到密码中。当散列密码存储在目录中时，盐值附加在散列密码后面。密码前缀`{SSHA}`，以便 LDAP 目录知道需要以不同的方式比较用户提供的密码。大多数现代 LDAP 服务器将`SSHA`作为默认的密码存储算法。

# 密码比较认证的缺点

既然你已经了解了 LDAP 如何使用密码，并且我们已经设置了`PasswordComparisonAuthenticator`，那么你觉得如果你使用以`SSHA`格式存储密码的`sshauser@example.com`用户登录会发生什么？

好的，放下书本试试，然后回来。

你的登录被拒绝了，对吧？然而你还是能够以 SHA 编码密码的用户登录。为什么？当我们在使用绑定认证时，密码编码和存储很重要。你认为为什么？

使用绑定认证时，它不重要，因为 LDAP 服务器负责处理用户的认证和验证。使用密码比较认证时，Spring Security LDAP 负责以目录期望的格式编码密码，然后将其与目录进行匹配以验证认证。

出于安全考虑，密码比较认证实际上无法从目录中读取密码（读取目录密码通常被安全策略禁止）。相反，`PasswordComparisonAuthenticator`执行一个以用户目录条目为根的 LDAP 搜索，试图与由 Spring Security 编码的密码的`password`属性和值相匹配。

所以，当我们尝试使用`sshauser@example.com`登录时，`PasswordComparisonAuthenticator`正在使用配置的`SHA`算法编码密码，并尝试进行简单匹配，这失败了，因为该用户的目录密码以`SSHA`格式存储。

我们当前的配置已使用`LdapShaPasswordEncoder`支持了`SHA`和`SSHA`，所以目前仍然无法工作。让我们来思考可能的原因。记住，`SSHA`使用的是加盐密码，盐值与密码一起存储在 LDAP 目录中。然而，`PasswordComparisonAuthenticator`的编码方式使其无法从 LDAP 服务器读取任何内容（这通常违反了不允许绑定的公司的安全策略）。因此，当`PasswordComparisonAuthenticator`计算散列密码时，它无法确定要使用哪个盐值。

总之，`PasswordComparisonAuthenticator` 在某些有限的特定情况下非常有价值，其中目录本身的安全性是一个关注点，但它永远不可能像直接绑定身份验证那样灵活。

# 配置 UserDetailsContextMapper 对象

如我们之前所提到的，`o.s.s.ldap.userdetails.UserDetailsContextMapper` 接口的一个实例用于将用户的 LDAP 服务器条目映射到内存中的 `UserDetails` 对象。默认的 `UserDetailsContextMapper` 对象行为类似于 `JpaDaoImpl`，考虑到返回的 `UserDetails` 对象中填充的详细信息级别 - 也就是说，除了用户名和密码之外，没有返回很多信息。

然而，LDAP 目录 potentially potentially 包含比用户名、密码和角色更多的个人信息。Spring Security 附带了两种从标准 LDAP 对象架构 - `person` 和 `inetOrgPerson` 中提取更多用户数据的方法。

# 隐式配置 UserDetailsContextMapper

为了配置一个不同的 `UserDetailsContextMapper` 实现，而不是默认的实现，我们只需要声明我们想要 `LdapAuthenticationProvider` 返回哪个 `LdapUserDetails` 类。安全命名空间解析器足够智能，可以根据请求的 `LdapUserDetails` 接口类型实例化正确的 `UserDetailsContextMapper` 实现。

让我们重新配置我们的 `SecurityConfig.java` 文件，以使用 `inetOrgPerson` 映射器版本。更新 `SecurityConfig.java` 文件，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
           .ldapAuthentication()
           .userSearchBase("")
           .userSearchFilter("(uid={0})")
           .groupSearchBase("ou=Groups")
           .groupSearchFilter("(uniqueMember={0})")
 .userDetailsContextMapper( new InetOrgPersonContextMapper())           .contextSource(contextSource())
           .passwordCompare()
              // Supports {SHA} and {SSHA}
               .passwordEncoder(new LdapShaPasswordEncoder())
               .passwordAttribute("userPassword");
    }
```

如果我们移除 `passwordEncoder` 方法，那么使用 `SHA` 密码的 LDAP 用户将无法进行身份验证。

如果你重新启动应用程序并尝试以 LDAP 用户身份登录，你会看到什么都没有变化。实际上，`UserDetailsContextMapper` 在幕后已经更改为在用户目录条目中可用 `inetOrgPerson` 架构属性时读取附加详细信息。

尝试使用 `admin1@example.com` 作为 `username` 和 `admin1` 作为 `password` 进行身份验证。它应该无法进行身份验证。

# 查看附加用户详细信息

为了在这个领域帮助你，我们将向 JBCP 日历应用程序添加查看当前账户的能力。我们将使用这个页面来展示如何使用更丰富的个人和 `inetOrgPerson` LDAP 架构为您的 LDAP 应用程序提供额外的（可选）信息。

你可能注意到这一章带有一个额外的控制器，名为 `AccountController`。你可以看到相关的代码，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/web/controllers/AccountController.java

    ...
    @RequestMapping("/accounts/my")
    public String view(Model model) {
    Authentication authentication = SecurityContextHolder.
    getContext().getAuthentication();
    // null check on authentication omitted
    Object principal = authentication.getPrincipal();
    model.addAttribute("user", principal);
    model.addAttribute("isLdapUserDetails", principal instanceof
    LdapUserDetails);
    model.addAttribute("isLdapPerson", principal instanceof Person);
    model.addAttribute("isLdapInetOrgPerson", principal instanceof
    InetOrgPerson);
    return "accounts/show";
    }
    ...
```

前面的代码将通过`LdapAuthenticationProvider`从`Authentication`对象中检索存储在`UserDetails`对象（主体）中，并确定它是哪种类型的`LdapUserDetailsImplinterface`。页面代码本身将根据已绑定到用户认证信息的`UserDetails`对象类型显示各种详细信息，正如我们在下面的 JSP 代码中所看到的那样。我们已经包括了 JSP：

```java
    //src/main/resources/templates/accounts/show.html

    <dl>
       <dt>Username</dt>
       <dd id="username" th:text="${user.username}">ChuckNorris</dd>
       <dt>DN</dt>
       <dd id="dn" th:text="${user.dn}"></dd>
       <span th:if="${isLdapPerson}">
           <dt>Description</dt>
           <dd id="description" th:text="${user.description}"></dd>
           <dt>Telephone</dt>
           <dd id="telephoneNumber" th:text="${user.telephoneNumber}"></dd>
           <dt>Full Name(s)</dt>
           <span th:each="cn : ${user.cn}">
           <dd th:text="${cn}"></dd>
           </span>
       </span>
       <span th:if="${isLdapInetOrgPerson}">
           <dt>Email</dt>
           <dd id="email" th:text="${user.mail}"></dd>
           <dt>Street</dt>
           <dd id="street" th:text="${user.street}"></dd>
       </span>
    </dl>
```

实际需要做的工作只是在我们`header.html`文件中添加一个链接，如下面的代码片段所示：

```java
    //src/main/resources/templates/fragments/header.html

    <li>
    <p class="navbar-text">Welcome &nbsp;
 <a id="navMyAccount" th:href="@{/accounts/my}">         <div class="navbar-text" th:text="${#authentication.name}">
         User</div>
 </a>    </p>
    </li>
```

我们增加了以下两个用户，您可以使用它们来检查可用数据元素的区别：

| **用户名** | **密码** | **类型** |
| --- | --- | --- |
| `shainet@example.com` | `shainet` | `inetOrgPerson` |
| `shaperson@example.com` | `shaperson` | `person` |

您的代码应该像`chapter05.03-calendar`。

通过在右上角点击用户名，重新启动服务器并检查各种用户类型的账户详情页面。你会注意到，当`UserDetails`类配置为使用`inetOrgPerson`时，尽管返回的是`o.s.s.ldap.userdetails.InetOrgPerson`，但字段可能填充也可能不填充，这取决于目录条目的可用属性。

实际上，`inetOrgPerson`有更多我们在这个简单页面上说明的属性。您可以在*RFC 2798*中查看完整列表，《inetOrgPerson LDAP 对象类的定义》([`tools.ietf.org/html/rfc2798`](http://tools.ietf.org/html/rfc2798))。

您可能会注意到，没有支持在对象条目上指定但不符合标准架构的额外属性的功能。标准的`UserDetailsContextMapper`接口不支持任意属性的列表，但通过使用`userDetailsContextMapper`方法，仍然可以通过引用您自己的`UserDetailsContextMapper`接口来定制它。

# 使用替代密码属性

在某些情况下，可能需要使用替代的 LDAP 属性来进行身份验证，而不是`userPassword`。这可能发生在公司部署了自定义 LDAP 架构，或者不需要强密码管理（可以说，这从来不是一个好主意，但在现实世界中确实会发生）的情况下。

`PasswordComparisonAuthenticator`接口还支持将用户密码与替代的 LDAP 条目属性进行验证的能力，而不是标准的`userPassword`属性。这非常容易配置，我们可以通过使用明文`telephoneNumber`属性来演示一个简单的例子。按照以下方式更新`SecurityConfig.java`：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
         .ldapAuthentication()
         .userSearchBase("")
         .userSearchFilter("(uid={0})")
        .groupSearchBase("ou=Groups")
         .groupSearchFilter("(uniqueMember={0})")
         .userDetailsContextMapper(new InetOrgPersonContextMapper())
         .contextSource(contextSource())
         .passwordCompare()
            .passwordAttribute("telephoneNumber");
    }
```

我们可以重新启动服务器，并尝试使用`hasphone@example.com`作为`username`和`0123456789`作为`password`（电话号码）属性进行登录。

您的代码应该像`chapter05.04-calendar`。

当然，这种基于`PasswordComparisonAuthenticator`的认证方式具有我们之前讨论过的所有风险；然而，了解它是明智的，以防在 LDAP 实现中遇到它。

# 使用 LDAP 作为 UserDetailsService

需要指出的一点是，LDAP 也可以用作`UserDetailsService`。正如我们将在书中稍后讨论的，`UserDetailsService`是启用 Spring Security 基础架构中各种其他功能所必需的，包括记住我和 OpenID 认证功能。

我们将修改我们的`AccountController`对象，使其使用`LdapUserDetailsService`接口来获取用户。在这样做之前，请确保删除以下代码片段中的`passwordCompare`方法：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
         .ldapAuthentication()
         .userSearchFilter("(uid={0})")
         .groupSearchBase("ou=Groups")
         .userDetailsContextMapper(new InetOrgPersonContextMapper())
         .contextSource(contextSource());
    }
```

# 配置 LdapUserDetailsService

将 LDAP 配置为`UserDetailsService`的功能与配置 LDAP`AuthenticationProvider`非常相似。与 JDBC`UserDetailsService`一样，LDAP`UserDetailsService`接口被配置为`<http>`声明的兄弟。请对`SecurityConfig.java`文件进行以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
       return super.userDetailsService();
   }
```

从功能上讲，`o.s.s.ldap.userdetails.LdapUserDetailsService`的配置几乎与`LdapAuthenticationProvider`完全相同，不同之处在于这里没有尝试使用主体的用户名来绑定 LDAP。相反，`DefaultSpringSecurityContextSource`提供的凭据本身就是参考，用来执行用户查找。

不要犯一个非常常见的错误，即如果你打算使用 LDAP 本身来验证用户，就不要将`AuthenticationManagerBuilder`配置为引用`LdapUserDetailsService`的`UserDetailsService`！如前所述，由于安全原因，通常无法从 LDAP 中检索`password`属性，这使得`UserDetailsService`对于认证毫无用处。如前所述，`LdapUserDetailsService`使用与`DefaultSpringSecurityContextSource`声明一起提供的`baseDn`属性来获取其信息-这意味着它不会尝试将用户绑定到 LDAP，因此可能不会如你所预期的那样运行。

# 更新 AccountController 以使用 LdapUserDetailsService

现在我们将更新`AccountController`对象，使其使用`LdapDetailsUserDetailsService`接口来查找它显示的用户：

```java
    //src/main/java/com/packtpub/springsecurity/web/controllers/AccountController.java

    @Controller
    public class AccountController {
    private final UserDetailsService userDetailsService;
    @Autowired
    public AccountController(UserDetailsService userDetailsService) {
       this.userDetailsService = userDetailsService;
    }
    @RequestMapping("/accounts/my")
    public String view(Model model) {
       Authentication authentication = SecurityContextHolder.
       getContext().getAuthentication();
       // null check omitted
       String principalName = authentication.getName();
       Object principal = userDetailsService.
       loadUserByUsername(principalName);
       ...
    }
    }
```

显然，这个例子有点傻，但它演示了如何使用`LdapUserDetailsService`。请重新启动应用程序，使用`username`为`admin1@example.com`和`password`为`admin1`来尝试一下。你能弄清楚如何修改控制器以显示任意用户的信息吗？

你能弄清楚应该如何修改安全设置以限制管理员访问吗？

你的代码应该看起来像`chapter05.05-calendar`。

# 将 Spring Security 与外部 LDAP 服务器集成

测试了与嵌入式 LDAP 服务器的基本集成之后，你可能会想要与一个外部 LDAP 服务器进行交互。幸运的是，这非常直接，并且可以使用稍微不同的语法，外加我们提供给设置嵌入式 LDAP 服务器的相同的`DefaultSpringSecurityContextSource`指令来实现。

更新 Spring Security 配置以连接到端口`33389`的外部 LDAP 服务器，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
        .ldapAuthentication()
         .userSearchFilter("(uid={0})")
         .groupSearchBase("ou=Groups")
         .userDetailsContextMapper(new InetOrgPersonContextMapper())
         //.contextSource(contextSource())
 .contextSource() .managerDn("uid=admin,ou=system") .managerPassword("secret") .url("ldap://localhost:33389/dc=jbcpcalendar,dc=com");    }
```

这里的主要区别（除了 LDAP URL 之外）在于提供了账户的 DN 和密码。账户（实际上是可选的）应该被允许绑定到目录并在所有相关的 DN 上执行用户和组信息的搜索。这些凭据应用于 LDAP 服务器 URL 后，用于在 LDAP 安全系统中的其余 LDAP 操作。

请注意，许多 LDAP 服务器还支持通过 SSL 加密的 LDAP（LDAPS）——这当然是从安全角度考虑的首选，并且得到了 Spring LDAP 堆栈的支持。只需在 LDAP 服务器 URL 的开头使用`ldaps://`。LDAPS 通常运行在 TCP 端口`636`上。请注意，有许多商业和非商业的 LDAP 实现。您将用于连接性、用户绑定和`GrantedAuthoritys`填充的确切配置参数将完全取决于供应商和目录结构。在下一节中，我们将介绍一个非常常见的 LDAP 实现，即 Microsoft AD。

如果你没有可用的 LDAP 服务器并且想尝试一下，可以添加以下代码到你的`SecurityConfig.java`文件中，以此启动我们一直在使用的嵌入式 LDAP 服务器：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth
         .ldapAuthentication()
         .userSearchBase("")
         .userSearchFilter("(uid={0})")
         .groupSearchBase("ou=Groups")
         .groupSearchFilter("(uniqueMember={0})")
         .userDetailsContextMapper(new InetOrgPersonContextMapper())
 .contextSource() .managerDn("uid=admin,ou=system") .managerPassword("secret") .url("ldap://localhost:10389/dc=jbcpcalendar,dc=com") .root("dc=jbcpcalendar,dc=com") .ldif("classpath:/ldif/calendar.ldif")           .and()
               .passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder())
                .passwordAttribute("userPassword")
       ;
    }
```

如果这还不能让你信服，可以尝试使用 Apache Directory Studio 启动一个 LDAP 服务器，并把它里面的`calendar.ldif`文件导入进去。这样你就可以连接到外部的 LDAP 服务器了。然后重启应用程序，使用`username`为`shauser@example.com`和`password`为`shauser`来尝试这个。

你的代码应该看起来像`chapter05.06-calendar`。

# 显式 LDAP bean 配置

在本节中，我们将引导您完成一系列必要的 bean 配置，以显式配置与外部 LDAP 服务器的连接和实现对外部服务器进行身份验证所需的`LdapAuthenticationProvider`接口。与其他显式 bean-based 配置一样，除非您发现自己处于业务或技术要求无法支持安全命名空间配置方式的情况，否则您真的应该避免这样做。如果是这种情况，请继续阅读！

# 配置外部 LDAP 服务器引用

为了实现此配置，我们将假设我们有一个本地 LDAP 服务器正在端口`10389`上运行，具有与上一节中提供的`DefaultSpringSecurityContextSource`接口对应的相同配置。所需的 bean 定义已经在`SecurityConfig.java`文件中提供。实际上，为了保持事情简单，我们提供了整个`SecurityConfig.java`文件。请查看以下代码片段中的 LDAP 服务器参考：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public DefaultSpringSecurityContextSource contextSource() {return new    
    DefaultSpringSecurityContextSource(
       Arrays.asList("ldap://localhost:10389/"), 
       "dc=jbcpcalendar,dc=com"){{
          setUserDn("uid=admin,ou=system");
          setPassword("secret");
    }};
    }
```

接下来，我们需要配置`LdapAuthenticationProvider`，这有点复杂。

# 配置`LdapAuthenticationProvider`接口

如果您已经阅读并理解了本章中的解释，描述了 Spring Security LDAP 认证背后的原理，这个 bean 配置将完全可理解，尽管有点复杂。我们将使用以下特性配置`LdapAuthenticationProvider`：

+   用户凭据绑定认证（不进行密码比较）

+   在`UserDetailsContextMapper`中使用`InetOrgPerson`

请查看以下步骤：

1.  让我们开始吧-我们首先探索已经配置好的`LdapAuthenticationProvider`接口，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Bean
        public LdapAuthenticationProvider authenticationProvider 
        (BindAuthenticator ba,LdapAuthoritiesPopulator lap,
         \UserDetailsContextMapper cm){
            return new LdapAuthenticationProvider(ba, lap){{
              setUserDetailsContextMapper(cm);
           }};
        }
```

1.  下一个为我们提供的 bean 是`BindAuthenticator`，支持`FilterBasedLdapUserSearch`bean 用于在 LDAP 目录中定位用户 DN，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Bean
        public BindAuthenticator bindAuthenticator
        (FilterBasedLdapUserSearch userSearch)
        {
            return new BindAuthenticator(contextSource()){{
               setUserSearch(userSearch);
           }};
       }
        @Bean
        public FilterBasedLdapUserSearch filterBasedLdapUserSearch(){
           return new FilterBasedLdapUserSearch("", 
           //user-search-base "(uid={0})", //user-search-filter
           contextSource()); //ldapServer
        }
```

最后，`LdapAuthoritiesPopulator`和`UserDetailsContextMapper`执行我们本章早些时候探讨的角色：

```java
            //src/main/java/com/packtpub/springsecurity/configuration/
            SecurityConfig.java

            @Bean
            public LdapAuthoritiesPopulator authoritiesPopulator(){
               return new DefaultLdapAuthoritiesPopulator(contextSource(),
               "ou=Groups"){{
                  setGroupSearchFilter("(uniqueMember={0})");
           }};
        }
        @Bean
        public userDetailsContextMapper userDetailsContextMapper(){
           return new InetOrgPersonContextMapper();
        }
```

1.  在下一步中，我们必须更新 Spring Security 以使用我们显式配置的`LdapAuthenticationProvider`接口。更新`SecurityConfig.java`文件以使用我们的新配置，确保您删除旧的`ldapAuthentication`方法，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

 @Autowired private LdapAuthenticationProvider authenticationProvider;        @Override
        public void configure(AuthenticationManagerBuilder auth)
        throws Exception {
 auth.authenticationProvider(authenticationProvider);        }
```

至此，我们已经使用显式的 Spring bean 表示法完全配置了 LDAP 身份验证。在 LDAP 集成中使用此技术在某些情况下是有用的，例如当安全命名空间不暴露某些配置属性，或者需要提供针对特定业务场景的自定义实现类时。我们将在本章后面探讨这样一个场景，即如何通过 LDAP 连接到 Microsoft AD。

1.  请启动应用程序并尝试使用`username`为`shauser@example.com`和`password`为`shauser`的配置。假设您有一个外部运行的 LDAP 服务器，或者您保留了对配置的内存中`DefaultSpringSecurityContextSource`对象，一切应该仍然可以正常工作。

您的代码应该看起来像`chapter05.07-calendar`。

# 将角色发现委派给 UserDetailsService

一种填充可用于显式 bean 配置的用户角色的技术是实现`UserDetailsService`中按用户名查找用户的支持，并从此来源获取`GrantedAuthority`对象。配置像替换带有`ldapAuthoritiesPopulator` ID 的 bean 一样简单，使用一个更新的`UserDetailsServiceLdapAuthoritiesPopulator`对象，带有对`UserDetailsService`的引用。确保您在`SecurityConfig.java`文件中进行以下更新，并确保您移除之前的`ldapAuthoritiesPopulator`bean 定义：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    //@Bean
    //public LdapAuthoritiesPopulator authoritiesPopulator(){
        //return new DefaultLdapAuthoritiesPopulator(contextSource(),
       //"ou=Groups"){{
              //setGroupSearchFilter("(uniqueMember={0})");
        //   }};
      //}
    @Bean
    public LdapAuthoritiesPopulator authoritiesPopulator(
       UserDetailsService userDetailsService){ 
 return new UserDetailsServiceLdapAuthoritiesPopulator
         (userDetailsService);
    }
```

我们还需要确保我们已经定义了`userDetailsService`。为了简单起见，请添加如下所示的内存`UserDetailsService`接口：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    @Override
    public UserDetailsManager userDetailsService() {
       InMemoryUserDetailsManager manager = new 
        InMemoryUserDetailsManager();
       manager.createUser(User.withUsername("user1@example.com")
       .password("user1").roles("USER").build());
       manager.createUser(
           User.withUsername("admin1@example.com")
               .password("admin1").roles("USER", "ADMIN").build());
       return manager;
    }
```

现在您应该能够使用`admin1@example.com`作为`username`和`admin1`作为`password`进行身份验证。当然，我们也可以用这种在内存中的`UserDetailsService`接口替换我们在第四章《基于 JDBC 的认证》和第五章《使用 Spring Data 的认证》中讨论的基于 JDBC 或 JPA 的接口。

您的代码应该看起来像`chapter05.08-calendar`。

您可能会注意到这种方法在管理上的问题是，用户名和角色必须在 LDAP 服务器和`UserDetailsService`使用的存储库中进行管理-这可能对于大型用户基础来说不是一个可扩展的模型。

这种情况更常见的使用方式是在需要通过 LDAP 身份验证来确保受保护应用程序的用户是有效的企业用户，但应用程序本身希望存储授权信息。这使得潜在的应用程序特定数据不会出现在 LDAP 目录中，这可以是一个有益的关注点分离。

# 通过 LDAP 集成微软 Active Directory

微软 AD 的一个方便的功能不仅仅是它与基于微软 Windows 的网络架构的无缝集成，而且还因为它可以配置为使用 LDAP 协议暴露 AD 的内容。如果您在一个大量利用微软 Windows 的公司工作，那么您很可能要针对您的 AD 实例进行任何 LDAP 集成。

根据您对微软 AD 的配置（以及目录管理员的配置意愿，以支持 Spring Security LDAP），您可能会在将 AD 信息映射到 Spring Security 系统中的用户`GrantedAuthority`对象上遇到困难，而不是在认证和绑定过程中遇到困难。

在我们 LDAP 浏览器中的 JBCP 日历企业 AD LDAP 树与以下屏幕截图相似：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/74fc3ac8-075b-42ea-8d1a-ba9e48752694.png)

这里您看不到的是我们之前在样本 LDAP 结构中看到的`ou=Groups`；这是因为 AD 将组成员资格存储在用户自身的 LDAP 条目的属性中。

让我们用最近学到的显式 bean 配置知识来编写一个`LdapAuthoritiesPopulator`的实现，这个实现可以从用户的`memberOf`属性中获取`GrantedAuthority`。在下一节中，你可以找到这个章节示例代码中提供的`ActiveDirectoryLdapAuthoritiesPopulator.java`文件：

```java
    //src/main/java/com/packtpub/springsecurity/ldap/userdetails/ad/
    ActiveDirectoryLdapAuthoritiesPopulator.java

    public final class ActiveDirectoryLdapAuthoritiesPopulator
    implements LdapAuthoritiesPopulator {
       public Collection<? extends GrantedAuthority>
         getGrantedAuthorities(DirContextOperations userData, String
          username) {
           String[] groups = userData.getStringAttributes("memberOf");
           List<GrantedAuthority> authorities = new 
            ArrayList<GrantedAuthority>();
         for (String group : groups) {
           LdapRdn authority = new DistinguishedName(group).removeLast();
           authorities.add(new SimpleGrantedAuthority
           (authority.getValue()));
       }
       return authorities;
    }
    }
```

现在，我们需要修改我们的配置以支持我们的 AD 结构。假设我们是从前一部分详细介绍的 bean 配置开始的，做以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
       return new DefaultSpringSecurityContextSource(Arrays.asList
       ("ldap://corp.jbcpcalendar.com/"), "dc=corp,dc=jbcpcalendar,
        dc=com"){{     
             setUserDn("CN=Administrator,CN=Users," +                  
             "DC=corp,DC=jbcpcalendar,DC=com");
             setPassword("admin123!");
       }};
    }
    @Bean
    public LdapAuthenticationProvider authenticationProvider(                                    
    BindAuthenticator ba, LdapAuthoritiesPopulator lap){
       // removed UserDetailsContextMapper
       return new LdapAuthenticationProvider(ba, lap);
    }
    @Bean
    public FilterBasedLdapUserSearch filterBasedLdapUserSearch(){
       return new FilterBasedLdapUserSearch("CN=Users", //user-search-base
 "(sAMAccountName={0})", //user-search-filter       contextSource()); //ldapServer
    }
    @Bean
    public LdapAuthoritiesPopulator authoritiesPopulator(){
 return new ActiveDirectoryLdapAuthoritiesPopulator();    }
```

如果你定义了它，你将希望在`SecurityConfig.java`文件中删除`UserDetailsService`声明。最后，你还需要从`AccountController`中删除对`UserDetailsService`的引用。

`sAMAccountName`属性是我们在标准 LDAP 条目中使用的`uid`属性的 AD 等效物。尽管大多数 AD LDAP 集成可能比这个例子更复杂，但这应该能给你一个起点，让你跳进去并探索你对 Spring Security LDAP 集成的内部工作原理的概念理解；即使是支持一个复杂的集成也会容易得多。

如果你想要运行这个示例，你需要一个运行中的 AD 实例，其模式与屏幕截图中显示的模式匹配。另一种选择是调整配置以匹配你的 AD 模式。玩转 AD 的一个简单方法是安装**Active Directory Lightweight Directory Services**，可以在[`www.microsoft.com/download/en/details.aspx?id=14683`](http://www.microsoft.com/download/en/details.aspx?id=14683)找到。你的代码应该看起来像`chapter05.09-calendar`。

# Spring Security 4.2 中的内置 AD 支持

Spring Security 在 Spring Security 3.1 中增加了 AD 支持。事实上，前一部分的`ActiveDirectoryLdapAuthoritiesPopulator`类就是基于新增加的支持。为了使用 Spring Security 4.2 中的内置支持，我们可以用以下配置替换我们的整个`SecurityConfig.java`文件：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public AuthenticationProvider authenticationProvider(){
 ActiveDirectoryLdapAuthenticationProvider ap = new 
       ActiveDirectoryLdapAuthenticationProvider("corp.jbcpcalendar.com",
       "ldap://corp.jbcpcalendar.com/");
 ap.setConvertSubErrorCodesToExceptions(true);       return ap;
    }
```

当然，如果你打算使用它，你需要确保将其连接到`AuthenticationManager`。我们已经完成了这一点，但你可以在以下代码片段中找到配置的样子：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Autowired
    private AuthenticationProvider authenticationProvider;
    @Override
    public void configure(AuthenticationManagerBuilder auth)
    throws Exception {
       auth.authenticationProvider(authenticationProvider);
   }
```

关于提供的`ActiveDirectoryLdapAuthenticationProvider`类，以下几点需要注意：

+   需要进行身份验证的用户必须能够绑定到 AD（没有管理员用户。

+   默认的方法是搜索用户的`memberOf`属性来填充用户的权限。

+   用户必须包含一个名为`userPrincipalName`的属性，其格式为`username@<domain>`。这里，`<domain>`是`ActiveDirectoryLdapAuthenticationProvider`的第一个构造参数。这是因为，在绑定发生之后，就是这样找到`memberOf`查找上下文的。

由于现实世界中发生的复杂 LDAP 部署，内置支持很可能会提供一个指导，告诉你如何与自定义 LDAP 架构集成。

# 摘要

我们看到，当请求时，LDAP 服务器可以可靠地提供认证和授权信息，以及丰富的用户配置文件信息。在本章中，我们介绍了 LDAP 术语和概念，以及 LDAP 目录可能如何通常组织以与 Spring Security 配合工作。我们还探索了从 Spring Security 配置文件中配置独立（嵌入式）和外部 LDAP 服务器的方法。

我们讨论了将用户对 LDAP 仓库的认证和授权，以及随后映射到 Spring Security 参与者。我们还了解了 LDAP 中认证方案、密码存储和安全机制的差异，以及它们在 Spring Security 中的处理方式。我们还学会了将用户详细属性从 LDAP 目录映射到`UserDetails`对象，以便在 LDAP 和 Spring 启用应用程序之间进行丰富的信息交换。我们还明确地为 LDAP 配置了 bean，并讨论了这种方法的优缺点。

我们还讨论了与 AD 的集成。

在下一章中，我们将讨论 Spring Security 的**记住我**功能，该功能允许用户会话在关闭浏览器后仍然安全地保持。


# 第七章：记住我服务

在本章中，我们将添加一个应用程序即使在会话过期且浏览器关闭后也能记住用户的功能。本章将涵盖以下主题：

+   讨论什么是记住我

+   学习如何使用基于**令牌的记住我**功能

+   讨论记住我有多安全，以及使其更安全的各种方法

+   启用基于持久性的记住我功能，以及使用它时要考虑的额外问题

+   介绍整体的记住我架构

+   学习如何创建一个限制在用户 IP 地址上的自定义记住我实现

# 什么是记住我？

为网站的常客提供的一个便利功能是记住我功能。此功能允许用户在浏览器关闭后选择被记住。在 Spring Security 中，这是通过在用户浏览器中存储一个记住我 cookie 来实现的。如果 Spring Security 识别到用户正在出示一个记住我 cookie，那么用户将自动登录应用程序，无需输入用户名或密码。

什么是 cookie？

Cookie 是客户端（即 Web 浏览器）保持状态的一种方式。有关 cookie 的更多信息，请参考其他在线资源，例如维基百科（[`en.wikipedia.org/wiki/HTTP_cookie`](http://en.wikipedia.org/wiki/HTTP_cookie)）。

Spring Security 在本章提供了以下两种不同的策略，我们将在此讨论：

+   第一个是基于令牌的记住我功能，它依赖于加密签名

+   第二个方法，基于**持久性的记住我**功能，需要一个数据存储（数据库）

如我们之前提到的，我们将在本章中详细讨论这些策略。为了启用记住我功能，必须显式配置记住我功能。让我们先尝试基于令牌的记住我功能，看看它如何影响登录体验的流程。

# 依赖项

基于令牌的记住我部分除了第第二章 *Spring Security 入门*中的基本设置外，不需要其他依赖项。然而，如果你正在使用基于持久性的记住我功能，你需要在你的`pom.xml`文件中包含以下额外的依赖项。我们已经在章节的示例中包含了这些依赖项，所以不需要更新示例应用程序：

```java
    //build.gradle

    dependencies {
    // JPA / ORM / Hibernate:
 compile('org.springframework.boot:spring-boot-starter-data-jpa')    // H2 RDBMS
 runtime('com.h2database:h2')       ...
    }
```

# 基于令牌的记住我功能

Spring Security 提供了记住我功能的两种不同实现。我们将首先探索如何设置基于令牌的记住我服务。

# 配置基于令牌的记住我功能

完成此练习将允许我们提供一种简单且安全的方法，使用户在较长时间内保持登录。开始时，请执行以下步骤：

1.  修改`SecurityConfig.java`配置文件，添加`rememberMe`方法。

请查看以下代码片段：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Override
        protected void configure(HttpSecurity http) throws Exception {
           ...
           http.rememberMe().key("jbcpCalendar")
           ...
        }
```

你应该从`chapter07.00-calendar`开始。

1.  如果我们现在尝试运行应用程序，我们会发现流程中没有不同。这是因为我们还需要在登录表单中添加一个字段，允许用户选择此功能。编辑`login.html`文件，并添加一个复选框，如下面的代码片段所示：

```java
        //src/main/resources/templates/login.html

        <input type="password" id="password" name="password"/>
 <label for="remember-me">Remember Me?</label> <input type="checkbox" id="remember-me" name="remember_me" value="true"/>
        <div class="form-actions">
           <input id="submit" class="btn" name="submit" type="submit" 
           value="Login"/>
        </div>
```

您的代码应该看起来像`chapter07.01-calendar`。

1.  当我们下次登录时，如果选择了记住我框，则在用户的浏览器中设置了记住我 cookie。

Spring Security 理解它应该通过检查 HTTP 参数`remember_me`来记住用户。

在 Spring Security 3.1 及更早版本中，记住我表单字段的默认参数是`spring_security_remember_me`。现在，在 Spring Security 4.x 中，默认的记住我表单字段是`remember-me`。这可以通过`rememberMeParameter`方法来覆盖。

1.  如果用户然后关闭他的浏览器，重新打开它以登录 JBCP 日历网站的认证页面，他/她不会第二次看到登录页面。现在试试自己-选择记住我选项登录，将主页添加到书签中，然后重新启动浏览器并访问主页。您会看到，您会立即成功登录，而无需再次提供登录凭据。如果这种情况出现在您身上，这意味着您的浏览器或浏览器插件正在恢复会话。

先尝试关闭标签页，然后再关闭浏览器。

另一个有效的方法是使用浏览器插件，如**Firebug**（[`addons.mozilla.org/en-US/firefox/addon/firebug/`](https://addons.mozilla.org/en-US/firefox/addon/firebug/)），以删除`JSESSIONID`cookie。这通常可以在开发和验证您网站上此类功能时节省时间和烦恼。

登录后选择记住我，你应该会看到已经设置了两个 cookie，`JSESSIONID`和`remember-me`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/486134eb-1413-42f7-b94d-70070a43966b.png)

# 基于令牌的记住我功能是如何工作的

记住我功能在用户的浏览器中设置一个 cookie，包含一个 Base64 编码的字符串，包含以下内容：

+   用户名

+   过期日期/时间

+   `expiration`日期/时间的 MD5 散列值、`username`、`password`以及`rememberMe`方法的`key`属性。

这些被组合成一个单一的 cookie 值，存储在浏览器中供以后使用。

# MD5

MD5 是几种著名的加密散列算法之一。加密散列算法计算具有任意长度的输入数据的最紧凑且唯一的文本表示，称为**摘要**。这个摘要可以用来确定是否应该信任一个不可信的输入，通过将不可信输入的摘要与预期输入的有效摘要进行比较。

以下图表说明了它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/a2fb3cec-4da4-4033-ba05-b83fac2bfa16.png)

例如，许多开源软件网站允许镜像站点分发它们的软件，以帮助提高下载速度。然而，作为软件的用户，我们希望确保软件是真实的，并且不包含任何病毒。软件分发商将计算并在其网站上发布与他们已知的好版本软件对应的预期 MD5 校验和。然后，我们可以从任何位置下载文件。在安装软件之前，我们对下载的文件计算不信任的 MD5 校验和。然后，我们将不信任的 MD5 校验和与预期的 MD5 校验和进行比较。如果这两个值匹配，我们就知道可以安全地安装我们下载的文件。如果这两个值不匹配，我们不应该信任下载的文件并删除它。

尽管无法从哈希值中获取原始数据，但 MD5 算法存在多种攻击风险，包括利用算法本身的弱点以及彩虹表攻击。彩虹表通常包含数百万输入值预先计算的哈希值。这使得攻击者可以在彩虹表中查找哈希值，并确定实际的（未哈希）值。Spring Security 通过在哈希值中包括过期日期、用户的密码和记住我键来对抗这种风险。

# 记住我签名

我们可以看到 MD5 如何确保我们下载了正确的文件，但这与 Spring Security 的记住我服务有何关联呢？与下载的文件类似，cookie 是不信任的，但如果我们能验证来自我们应用程序的签名，我们就可以信任它。当带有记住我 cookie 的请求到来时，其内容被提取，期望的签名与 cookie 中找到的签名进行比较。计算期望签名的步骤在下图中说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/6014f753-534c-4041-84e4-f55339e3c5a8.png)

记住我 cookie 包含**用户名**、**过期时间**和一个**签名**。Spring Security 将从中提取**用户名**和**过期时间**。然后使用来自 cookie 的`username`通过`UserDetailsService`查找**密码**。**密钥**已知，因为它是通过`rememberMe`方法提供的。现在所有参数都知道了，Spring Security 可以使用**用户名**、**过期时间**、**密码**和**密钥**计算期望的签名。然后，它将期望签名与 cookie 中的**签名**进行比较。

如果两个签名匹配，我们可以确信**用户名**和**过期日期**是有效的。不知道记住我密钥（只有应用程序知道）和用户密码（只有这个用户知道）的情况下伪造签名几乎是不可能的。这意味着如果签名匹配且令牌没有过期，用户可以登录。

您可能已经预见到，如果用户更改了他们的用户名或密码，设置的任何记住我令牌将不再有效。确保如果您允许用户更改账户这些部分，您要向用户提供适当的消息。在本章后面，我们将查看一个仅依赖于用户名而非密码的替代记住我实现。

请注意，仍然可以区分已通过记住我 cookie 进行身份验证的用户和提供用户名和密码（或等效）凭据的用户。当我们调查记住我功能的安全性时，我们将很快尝试这一点。

# 基于令牌的记住我配置指令

以下是对记住我功能默认行为进行更改的两个常见配置更改：

| **属性** | **描述** |
| --- | --- |
| `key` | 定义用于生成记住我 cookie 签名时使用的唯一键。 |
| `tokenValiditySeconds` | 定义时间长度（以秒为单位）。记住我 cookie 将被视为用于身份验证的有效 cookie。它还用于设置 cookie 的过期时间戳。 |

正如您可能从讨论 cookie 内容是如何散列中推断出`key`属性对记住我功能的安全性至关重要。确保您选择的键很可能是您应用程序唯一的，并且足够长，以至于它不能轻易被猜测。

考虑到本书的目的，我们保留了键值相对简单，但如果你在自己的应用程序中使用记住我，建议你的键包含应用程序的唯一名称，并且至少 36 个随机字符长。密码生成工具（在 Google 中搜索“在线密码生成器”）是获得假随机字母数字和特殊字符混合来组成你的记住我键的好方法。对于存在于多个环境中的应用程序（例如开发、测试和生产），记住我 cookie 值也应该包括这个事实。这将防止在测试过程中无意中使用错误的环境的记住我 cookie！

生产应用程序中的一个示例键值可能与以下内容相似：

```java
    prodJbcpCalendar-rmkey-paLLwApsifs24THosE62scabWow78PEaCh99Jus
```

`tokenValiditySeconds`方法用于设置记住我令牌在自动登录功能中不再被接受的时间秒数，即使它本身是一个有效的令牌。相同的属性也用于设置用户浏览器上记住我 cookie 的最大生命周期。

记住我会话 cookie 的配置

如果`tokenValiditySeconds`设置为`-1`，登录 cookie 将被设置为会话 cookie，用户关闭浏览器后它不会持续存在。令牌将在用户不关闭浏览器的情况下，有效期为两周的不可配置长度。不要将此与存储用户会话 ID 的 cookie 混淆——它们名称相似，但完全是两回事！

您可能注意到我们列出的属性非常少。别担心，我们将在本章中花时间介绍一些其他配置属性。

# 记住我是否安全？

任何为了用户方便而添加的安全相关特性都有可能使我们精心保护的网站面临安全风险。默认形式的记住我功能，存在用户 cookie 被拦截并恶意用户重复使用的风险。以下图表说明了这可能如何发生：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/427022e2-68c7-4f5e-9be9-7bdec7389b27.png)

使用 SSL（在附录*附加参考资料*中有所涉及）和其他网络安全技术可以减轻这类攻击，但要注意还有其他技术，比如**跨站脚本攻击**（**XSS**），可能会窃取或破坏记住的用户会话。虽然这对用户方便，但如果我们不慎使用记住的会话，可能会导致财务或其他个人信息被无意修改或可能被盗用。

虽然本书没有详细讨论恶意用户行为，但在实现任何安全系统时，了解可能试图攻击您客户或员工的用户所采用的技术是很重要的。XSS 就是这样的技术，但还有很多其他技术。强烈建议您查阅*OWASP 前十名文章*（[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](http://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)）获取一个不错的列表，并且也可以获取一本关于网络应用安全性的参考书籍，在这本书中，许多演示的技术都适用于任何技术。

保持方便和安全之间平衡的一种常见方法是识别网站上可能存在个人或敏感信息的职能位置。然后，您可以使用`fullyAuthenticated`表达式确保这些位置通过检查用户角色以及他们是否使用完整用户名和密码进行身份验证的保护。我们将在下一节更详细地探讨这一特性。

# 记住我功能的授权规则

我们将在第十一章细粒度访问控制*中全面探讨高级授权技术*，不过，重要的是要意识到可以根据记住的认证会话与否来区分访问规则。

假设我们想要限制尝试访问 H2 `admin` 控制台的用户只能是使用用户名和密码认证的管理员。这与其他主要面向消费者的商业网站的行为类似，这些网站在输入密码之前限制对网站高级部分的访问。请记住，每个网站都是不同的，所以不要盲目地将此类规则应用于您的安全网站。对于我们的示例应用程序，我们将专注于保护 H2 数据库控制台。更新`SecurityConfig.java`文件以使用关键词`fullyAuthenticated`，确保尝试访问 H2 数据库的记住用户被拒绝访问。这显示在下面的代码片段中：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       ...
       http.authorizeRequests()
 .antMatchers("/admin/*") .access("hasRole(ADMIN) and isFullyAuthenticated()")       ...
       http.rememberMe().key("jbcpCalendar")
    }
```

现有的规则保持不变。我们增加了一条规则，要求查询账户信息时必须拥有适当的`GrantedAuthority` of `ROLE_ADMIN`，并且用户已经完全认证；也就是说，在这个认证会话期间，他们实际上提供了一个用户名和密码或其他合适的凭据。注意这里 SpEL 逻辑运算符的语法-`AND`，`OR`和`NOT`用于 SpEL 中的逻辑运算符。SpEL 设计者考虑得很周到，因为`&&`运算符在 XML 中表示起来会很不方便，尽管前面的例子是使用基于 Java 的配置！

你的代码应该看起来像`chapter07.02-calendar`。

登录使用用户名`admin1@example.com`和密码`admin1`，确保选择记住我功能。访问 H2 数据库控制台，你会看到访问被授权。现在，删除`JSESSIONID` cookie（或者关闭标签页，然后关闭所有浏览器实例），确保仍然可以访问所有事件页面。现在，导航到 H2 控制台，观察访问被拒绝。

这种方法结合了记住我功能的易用性增强和通过要求用户提供完整的凭据来访问敏感信息的安全性。在本章的其余部分，我们将探讨其他使记住我功能更加安全的方法。

# 持久的记住我

Spring Security 提供了通过利用`RememberMeServices`接口的不同实现来更改验证记住我 cookie 的方法的能力。在本节中，我们将讨论如何使用数据库来持久记住我令牌，以及这如何提高我们应用程序的安全性。

# 使用基于持久性的记住我功能

在此点修改我们的记住我配置以持久化到数据库是出奇地简单。Spring Security 配置解析器将识别`rememberMe`方法上的新`tokenRepository`方法，只需切换实现类即可`RememberMeServices`。现在让我们回顾一下完成此操作所需的步骤。

# 添加 SQL 创建记住我模式

我们将包含预期模式的 SQL 文件放在了`resources`文件夹中，位置与第三章 *自定义认证*中的位置相同。您可以在下面的代码片段中查看模式定义：

```java
    //src/main/resources/schema.sql

    ...
    create table persistent_logins (
       username varchar_ignorecase(100) not null,
       series varchar(64) primary key,
       token varchar(64) not null,
       last_used timestamp not null
    );
    ...
```

# 使用记住我模式初始化数据源

Spring Data 将自动使用`schema.sql`初始化嵌入式数据库，如前一部分所述。请注意，但是，对于 JPA，为了创建模式并使用`data.sql`文件来种子数据库，我们必须确保设置了`ddl-auto`到 none，如下面的代码所示：

```java
    //src/main/resources/application.yml

    spring:
    jpa:
       database-platform: org.hibernate.dialect.H2Dialect
       hibernate:
 ddl-auto: none
```

# 配置基于持久化的记住我功能

最后，我们需要对`rememberMe`声明进行一些简要的配置更改，以指向我们正在使用的数据源，如下面的代码片段所示：

```java
   //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

   @Autowired
   @SuppressWarnings("SpringJavaAutowiringInspection")
 private DataSource dataSource;    @Autowired
 private PersistentTokenRepository persistentTokenRepository;    @Override
    protected void configure(HttpSecurity http) throws Exception {
       ...
       http.rememberMe()
           .key("jbcpCalendar")
 .tokenRepository(persistentTokenRepository)       ...
    }
 @Bean public PersistentTokenRepository persistentTokenRepository() { JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl(); db.setDataSource(dataSource); return db; }
```

这就是我们需要做的，以便切换到基于持久化的记住我认证。大胆地启动应用程序并尝试一下。从用户的角度来看，我们感觉不到任何区别，但我们知道支持这个功能的实现已经发生了变化。

您的代码应该看起来像`chapter07.03-calendar`。

# 持久化基于的记住我功能是如何工作的？

持久化基于的记住我服务不是验证 cookie 中的签名，而是验证令牌是否存在于数据库中。每个持久记住我 cookie 包括以下内容：

+   **序列标识符**：这标识了用户的初始登录，并且每次用户自动登录到原始会话时都保持一致。

+   **令牌值**：每次用户使用记住我功能进行身份验证时都会变化的唯一值。

请查看以下图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/2e71b059-a28a-4b0f-955d-453845a6dbd1.png)

当记住我 cookie 提交时，Spring Security 将使用`o.s.s.web.authentication.rememberme.PersistentTokenRepository`实现来查找期望的令牌值和使用提交序列标识的过期时间。然后，它将比较 cookie 中的令牌值与期望的令牌值。如果令牌没有过期且两个令牌匹配，用户被认为是认证的。将生成一个新的记住我 cookie，具有相同的序列标识符、新的令牌值和更新的过期日期。

如果在数据库中找到了提交的序列令牌，但令牌不匹配，可以假设有人偷了记住我 cookie。在这种情况下，Spring Security 将终止这些记住我令牌，并警告用户他们的登录已经被泄露。

存储的令牌可以在数据库中找到，并通过 H2 控制台查看，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/e467fa2a-2bf3-4c0a-b650-60d0fac32b1c.png)

# JPA 基础持久化令牌存储库

正如我们之前章节所看到的，使用 Spring Data 项目来映射我们的数据库可以大大简化我们的工作。因此，为了保持一致性，我们将重构我们的基于 JDBC 的`PersistentTokenRepository`接口，该接口使用`JdbcTokenRepositoryImpl`，改为基于 JPA 的。我们将通过执行以下步骤来实现：

1.  首先，让我们创建一个领域对象来保存持久登录，如下面的代码片段所示：

```java
        //src/main/java/com/packtpub/springsecurity/domain/
        PersistentLogin.java 

        import org.springframework.security.web.authentication.rememberme.
        PersistentRememberMeToken;
        import javax.persistence.*;
        import java.io.Serializable;
        import java.util.Date;
        @Entity
        @Table(name = "persistent_logins")
        public class PersistentLogin implements Serializable {
           @Id
           private String series;
           private String username;
           private String token;
           private Date lastUsed;
           public PersistentLogin(){}
           public PersistentLogin(PersistentRememberMeToken token){
               this.series = token.getSeries();
               this.username = token.getUsername();
               this.token = token.getTokenValue();
               this.lastUsed = token.getDate();
           }
          ...
```

1.  接下来，我们需要创建一个`o.s.d.jpa.repository.JpaRepository`仓库实例，如下面的代码片段所示：

```java
        //src/main/java/com/packtpub/springsecurity/repository/
        RememberMeTokenRepository.java

        import com.packtpub.springsecurity.domain.PersistentLogin;
        import org.springframework.data.jpa.repository.JpaRepository;
        import java.util.List;
        public interface RememberMeTokenRepository extends  
        JpaRepository<PersistentLogin, String> {
            PersistentLogin findBySeries(String series);
            List<PersistentLogin> findByUsername(String username);
        }
```

1.  现在，我们需要创建一个自定义的`PersistentTokenRepository`接口来替换`Jdbc`实现。我们必须重写四个方法，但代码应该相当熟悉，因为我们所有操作都将使用 JPA：

```java
         //src/main/java/com/packtpub/springsecurity/web/authentication/
         rememberme/JpaPersistentTokenRepository.java:

         ...
         public class JpaPersistentTokenRepository implements 
         PersistentTokenRepository {
               private RememberMeTokenRepository rememberMeTokenRepository;
               public JpaPersistentTokenRepository
               (RememberMeTokenRepository rmtr) {
                  this.rememberMeTokenRepository = rmtr;
           }
           @Override
           public void createNewToken(PersistentRememberMeToken token) {
               PersistentLogin newToken = new PersistentLogin(token);
               this.rememberMeTokenRepository.save(newToken);
           }
          @Override
          public void updateToken(String series, String tokenValue, 
          Date lastUsed) {
               PersistentLogin token = this.rememberMeTokenRepository
               .findBySeries(series);
               if (token != null) {
                   token.setToken(tokenValue);
                   token.setLastUsed(lastUsed);
                   this.rememberMeTokenRepository.save(token);
               }
           }
        @Override
           public PersistentRememberMeToken 
           getTokenForSeries(String seriesId) {
               PersistentLogin token = this.rememberMeTokenRepository
               .findBySeries(seriesId);
               return new PersistentRememberMeToken(token.getUsername(),
               token.getSeries(), token.getToken(), token.getLastUsed());
           }
           @Override
         public void removeUserTokens(String username) {
             List<PersistentLogin> tokens = this.rememberMeTokenRepository
             .findByUsername(username);
              this.rememberMeTokenRepository.delete(tokens);
           }
        }
```

1.  现在，我们需要在`SecurityConfig.java`文件中做些修改，以声明新的`PersistentTokenTokenRepository`接口，但其余的配置与上一节保持不变，如下面的代码片段所示：

```java
            //src/main/java/com/packtpub/springsecurity/configuration/
            SecurityConfig.java

            //@Autowired
            //@SuppressWarnings("SpringJavaAutowiringInspection")
            //private DataSource dataSource;
            @Autowired
 private PersistentTokenRepository persistentTokenRepository;            ...
 @Bean public PersistentTokenRepository persistentTokenRepository( RememberMeTokenRepository rmtr) { return new JpaPersistentTokenRepository(rmtr); }
```

1.  这就是我们将 JDBC 更改为基于 JPA 的持久化记住我认证所需要做的一切。现在启动应用程序并尝试一下。从用户的角度来看，我们并没有注意到任何区别，但我们知道支持这一功能的实现已经发生了变化。

你的代码应该看起来像`chapter07.04-calendar`。

# 自定义 RememberMeServices

到目前为止，我们使用了一个相当简单的`PersistentTokenRepository`实现。我们使用了基于 JDBC 和基于 JPA 的实现。这为 cookie 持久化提供了有限的控制；如果我们想要更多控制，我们将把我们自己的`PersistentTokenRepository`接口包装在`RememberMeServices`中。Barry Jaspan 有一篇关于*改进持久登录 Cookie 最佳实践*的优秀文章（[`jaspan.com/improved_persistent_login_cookie_best_practice`](http://jaspan.com/improved_persistent_login_cookie_best_practice)）。Spring Security 有一个略有修改的版本，如前所述，称为`PersistentTokenBasedRememberMeServices`，我们可以将其包装在我们的自定义`PersistentTokenRepository`接口中，并在我们的记住我服务中使用。

在下一节中，我们将把我们的现有`PersistentTokenRepository`接口包装在`PersistentTokenBasedRememberMeServices`中，并使用`rememberMeServices`方法将其连接到我们的记住我声明：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    //@Autowired
    //private PersistentTokenRepository persistentTokenRepository;
    @Autowired
    private RememberMeServices rememberMeServices;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       ...
       http.rememberMe()
           .key("jbcpCalendar")
 .rememberMeServices(rememberMeServices)       ...
    }
 @Bean public RememberMeServices rememberMeServices
    (PersistentTokenRepository ptr){ PersistentTokenBasedRememberMeServices rememberMeServices = new 
       PersistentTokenBasedRememberMeServices("jbcpCalendar", 
userDetailsService, ptr);
 rememberMeServices.setAlwaysRemember(true); return rememberMeServices; }
```

你的代码应该看起来像`chapter07.05-calendar`。

基于数据库的持久令牌是否更安全？

就像`TokenBasedRememberMeServices`一样，持久化令牌可能会因 cookie 窃取或其他中间人技术而受到威胁。正如附录中提到的，使用 SSL 可以绕过中间人技术。如果你正在使用 Servlet 3.0 环境（即 Tomcat 7+），Spring Security 会将 cookie 标记为`HttpOnly`，这将有助于减轻在应用程序中出现 XSS 漏洞时 cookie 被窃取的风险。要了解更多关于`HttpOnly`属性的信息，请参阅本章前面提供的关于 cookie 的外部资源。

使用基于持久化的记住我功能的一个优点是我们可以检测 cookie 是否被泄露。如果正确的一系列令牌和一个不正确的令牌被呈现，我们知道使用该系列令牌的任何记住我功能都应被视为被泄露，我们应该终止与它关联的任何会话。由于验证是状态 ful 的，我们还可以在不更改用户密码的情况下终止特定的记住我功能。

# 清理过期的记住我会话

使用基于持久化的记住我功能的缺点是，没有内置的支持来清理过期的会话。为了做到这一点，我们需要实现一个后台进程来清理过期的会话。我们在本章的示例代码中包含了用于执行清理的代码。

为了简洁起见，我们显示一个不执行验证或错误处理的版本，如下面的代码片段所示。你可以在本章的示例代码中查看完整版本：

```java
    //src/main/java/com/packtpub/springsecurity/web/authentication/rememberme/
    JpaTokenRepositoryCleaner.java

    public class JpaTokenRepositoryImplCleaner
    implements Runnable {
       private final RememberMeTokenRepository repository;
       private final long tokenValidityInMs;
       public JpaTokenRepositoryImplCleaner(RememberMeTokenRepository 
       repository, long tokenValidityInMs) {
           if (rememberMeTokenRepository == null) {
               throw new IllegalArgumentException("jdbcOperations cannot 
               be null");
           }
           if (tokenValidityInMs < 1) {
               throw new IllegalArgumentException("tokenValidityInMs 
               must be greater than 0\. Got " + tokenValidityInMs);
           }
           this. repository = repository;
           this.tokenValidityInMs = tokenValidityInMs;
       }
           public void run() {
           long expiredInMs = System.currentTimeMillis() 
           - tokenValidityInMs;             
              try {
               Iterable<PersistentLogin> expired = 
               rememberMeTokenRepository
               .findByLastUsedAfter(new Date(expiredInMs));
               for(PersistentLogin pl: expired){
                   rememberMeTokenRepository.delete(pl);
               }
           } catch(Throwable t) {...}
       }
    }
```

本章的示例代码还包括一个简单的 Spring 配置，每十分钟执行一次清理器。如果你不熟悉 Spring 的任务抽象并且想学习，那么你可能想阅读更多关于它在 Spring 参考文档中的内容：[`docs.spring.io/spring/docs/current/spring-framework-reference/html/scheduling.html`](https://docs.spring.io/spring/docs/current/spring-framework-reference/html/scheduling.html)。你可以在以下代码片段中找到相关的配置。为了清晰起见，我们将这个调度器放在`JavaConfig.java`文件中：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    JavaConfig.java@Configuration

    @Import({SecurityConfig.class})
 @EnableScheduling    public class JavaConfig {
 @Autowired private RememberMeTokenRepository rememberMeTokenRepository; @Scheduled(fixedRate = 10_000) public void tokenRepositoryCleaner(){ Thread trct = new Thread(new JpaTokenRepositoryCleaner(
 rememberMeTokenRepository, 60_000L));
 trct.start(); }    }
```

请记住，此配置不是集群友好的。因此，如果部署到集群，清理器将针对应用程序部署到的每个 JVM 执行一次。

启动应用程序并尝试更新。提供的配置将确保每十分钟执行一次清理器。你可能想让清理任务更频繁地运行，通过修改`@Scheduled`声明来清理最近使用的记住我令牌。然后，你可以创建几个记住我令牌，并通过在 H2 数据库控制台查询它们来查看它们是否被删除。

你的代码应该看起来像`chapter07.06-calendar`。

# 记住我架构

我们已经介绍了`TokenBasedRememberMeServices`和`PersistentTokenBasedRememberMeServices`的基本架构，但我们还没有描述总体架构。让我们看看所有 remember-me 部件是如何组合在一起的。

以下图表说明了验证基于令牌的 remember-me 令牌过程中涉及的不同组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/10ed330e-3d74-468b-bcc1-2ba08fc03532.png)

与 Spring Security 的任何一个过滤器一样，`RememberMeAuthenticationFilter`是从`FilterChainProxy`内部调用的。`RememberMeAuthenticationFilter`的工作是检查请求，如果它感兴趣，就采取行动。`RememberMeAuthenticationFilter`接口将使用`RememberMeServices`实现来确定用户是否已经登录。`RememberMeServices`接口通过检查 HTTP 请求中的 remember-me cookie，然后使用我们之前讨论过的基于令牌的验证或基于持久性的验证来验证。如果令牌检查无误，用户将登录。

# Remember-me 与用户生命周期

`RememberMeServices`的实现在整个用户生命周期中（认证用户的会话生命周期）的几个点被调用。为了帮助您理解 remember-me 功能，了解 remember-me 服务在生命周期功能通知的时间点可能会有所帮助：

| **操作** | **应该发生什么？** | **调用的 RememberMeServices 方法** |
| --- | --- | --- |
| 登录成功 | 实现设置 remember-me cookie（如果已发送`form`参数） | `loginSuccess` |
| 登录失败 | 如果存在，实现应取消 cookie | `loginFailed` |
| 用户登出 | 如果存在，实现应取消 cookie | `logout` |

`RememberMeServices`接口上没有`logout`方法。相反，每个`RememberMeServices`实现也实现了`LogoutHandler`接口，该接口包含了`logout`方法。通过实现`LogoutHandler`接口，每个`RememberMeServices`实现可以在用户登出时执行必要的清理工作。

了解`RememberMeServices`在哪里以及如何与用户的生命周期相关联，在我们开始创建自定义认证处理程序时将非常重要，因为我们需要确保任何认证处理器一致地对待`RememberMeServices`，以保持这种功能的有效性和安全性。

# 限制 remember-me 功能到 IP 地址

让我们把我们对记住我架构的理解付诸实践。一个常见的要求是，任何记住我令牌都应与创建它的用户的 IP 地址绑定。这为记住我功能增加了额外的安全性。为此，我们只需要实现一个自定义的`PersistentTokenRepository`接口。我们将要做的配置更改将说明如何配置自定义的`RememberMeServices`。在本节中，我们将查看`IpAwarePersistentTokenRepository`，该类包含在章节源代码中。`IpAwarePersistentTokenRepository`接口确保内部将系列标识与当前用户的 IP 地址结合，而外部仅包含标识。这意味着无论何时查找或保存令牌，都会使用当前 IP 地址来查找或持久化令牌。在以下代码片段中，你可以看到`IpAwarePersistentTokenRepository`是如何工作的。如果你想要更深入地了解，我们鼓励你查看随章节提供的源代码。

查找 IP 地址的技巧是使用 Spring Security 的`RequestContextHolder`。相关代码如下：

需要注意的是，为了使用`RequestContextHolder`，你需要确保你已经设置了你的`web.xml`文件以使用`RequestContextListener`。我们已经为我们的示例代码完成了这个设置。然而，这在使用示例代码的外部应用程序中可能很有用。参考`IpAwarePersistentTokenRepository`的 Javadoc，了解如何进行此设置的详细信息。

请查看以下代码片段：

```java
    //src/main/java/com/packtpub/springsecurity/web/authentication/rememberme/
    IpAwarePersistentTokenRepository.java

    private String ipSeries(String series) {
    ServletRequestAttributes attributes = (ServletRequestAttributes)
    RequestContextHolder.getRequestAttributes();
    return series + attributes.getRequest().getRemoteAddr();
    }
```

我们可以在此基础上构建方法，强制保存的令牌中包含在系列标识中的 IP 地址，如下所示：

```java
    public void createNewToken(PersistentRememberMeToken token) {
      String ipSeries = ipSeries(token.getSeries());
      PersistentRememberMeToken ipToken = tokenWithSeries(token, ipSeries);
      this.delegateRepository.createNewToken(ipToken);
    }
```

你可以看到我们首先创建了一个新的系列，并将其与 IP 地址连接起来。`tokenWithSeries`方法只是一个创建具有所有相同值的新令牌的助手，除了新的系列。然后我们将包含 IP 地址的新系列标识的新令牌提交给`delegateRepsository`，这是`PersistentTokenRepository`的原始实现。

无论何时查找令牌，我们都要求将当前用户的 IP 地址附加到系列标识上。这意味着用户无法获取不同 IP 地址的用户的令牌：

```java
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
       String ipSeries = ipSeries(seriesId);
       PersistentRememberMeToken ipToken = delegateRepository.
       getTokenForSeries(ipSeries);
       return tokenWithSeries(ipToken, seriesId);
    }
```

剩余的代码非常相似。内部我们构建的系列标识将附加到 IP 地址上，外部我们只展示原始系列标识。通过这样做，我们实施了这样的约束：只有创建了记住我令牌的用户才能使用它。

让我们回顾一下本章示例代码中包含的 Spring 配置，用于`IpAwarePersistentTokenRepository`。在以下代码片段中，我们首先创建了一个`IpAwarePersistentTokenRepository`声明，它包装了一个新的`JpaPersistentTokenRepository`声明。然后通过实例化`OrderedRequestContextFilter`接口来初始化一个`RequestContextFilter`类：

```java
    //src/main/java/com/packtpub/springsecurity/web/configuration/WebMvcConfig.java

    @Bean
    public IpAwarePersistentTokenRepository 
    tokenRepository(RememberMeTokenRepository rmtr) {
       return new IpAwarePersistentTokenRepository(
               new JpaPersistentTokenRepository(rmtr)
       );
    }
    @Bean
    public OrderedRequestContextFilter requestContextFilter() {
       return new OrderedRequestContextFilter();
    }
```

为了让 Spring Security 使用我们的自定义`RememberMeServices`，我们需要更新我们的安全配置以指向它。接着，在`SecurityConfig.java`中进行以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

     @Override
     protected void configure(HttpSecurity http) throws Exception {
       ...
       // remember me configuration
      http.rememberMe()
           .key("jbcpCalendar")
 .rememberMeServices(rememberMeServices);     }
    @Bean
 public RememberMeServices rememberMeServices
    (PersistentTokenRepository ptr){
       PersistentTokenBasedRememberMeServices rememberMeServices = new 
       PersistentTokenBasedRememberMeServices("jbcpCalendar", 
       userDetailsService, ptr);
       return rememberMeServices;
    }
```

现在，大胆尝试启动应用程序。您可以使用第二台计算机和插件（如 Firebug），来操作您的 remember-me cookie。如果您尝试从一个计算机使用 remember-me cookie 在另一台计算机上，Spring Security 现在将忽略 remember-me 请求并删除相关 cookie。

您的代码应类似于`chapter07.07-calendar`。

请注意，基于 IP 的 remember-me 令牌如果用户位于共享或负载均衡的网络基础架构后面，例如多 WAN 企业环境，可能会出现意外行为。然而，在大多数场景下，向 remember-me 功能添加 IP 地址为用户提供了一个额外的、受欢迎的安全层。

# 自定义 cookie 和 HTTP 参数名称

好奇的用户可能会想知道 remember-me 表单字段的预期值是否可以更改为 remember-me，或者 cookie 名称是否可以更改为 remember-me，以使 Spring Security 的使用变得模糊。这个更改可以在两个位置中的一个进行。请按照以下步骤查看：

1.  首先，我们可以在`rememberMe`方法中添加额外的方法，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        http.rememberMe()
               .key("jbcpCalendar")
 .rememberMeParameter("jbcpCalendar-remember-me") .rememberMeCookieName("jbcpCalendar-remember-me");
```

1.  此外，既然我们已经将自定义的`RememberMeServices`实现声明为 Spring bean，我们只需定义更多的属性来更改复选框和 cookie 名称，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Bean
        public RememberMeServices rememberMeServices
        (PersistentTokenRepository ptr){
           PersistentTokenBasedRememberMeServices rememberMeServices = new 
           PersistentTokenBasedRememberMeServices("jbcpCalendar", 
           userDetailsService, ptr);
 rememberMeServices.setParameter("obscure-remember-me"); rememberMeServices.setCookieName("obscure-remember-me");           return rememberMeServices;
        }
```

1.  不要忘记将`login.html`页面更改为设置复选框`form`字段的名称，并与我们声明的参数值相匹配。接着，按照以下内容更新`login.html`：

```java
        //src/main/resources/templates/login.html

        <input type="checkbox" id="remember" name=" obscure-remember-me" 
        value="true"/>
```

1.  我们鼓励您在此处进行实验，以确保您了解这些设置之间的关系。大胆尝试启动应用程序并尝试一下。

您的代码应类似于`chapter07.08-calendar`。

# 总结

本章解释并演示了 Spring Security 中 remember-me 功能的用法。我们从最基本的设置开始，学习了如何逐步使该功能更加安全。具体来说，我们了解了基于令牌的 remember-me 服务以及如何对其进行配置。我们还探讨了基于持久性的 remember-me 服务如何提供额外的安全功能，它是如何工作的，以及在使用它们时需要考虑的额外因素。

我们还介绍了创建自定义 remember-me 实现的过程，该实现将 remember-me 令牌限制为特定的 IP 地址。我们还看到了使 remember-me 功能更加安全的各种其他方法。

接下来是基于证书的认证，我们将讨论如何使用受信任的客户端证书来进行认证。
