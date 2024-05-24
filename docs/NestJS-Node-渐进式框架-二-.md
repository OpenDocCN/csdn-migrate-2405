# NestJS：Node 渐进式框架（二）

> 原文：[`zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240`](https://zh.annas-archive.org/md5/04CAAD35859143A3EB7D2A8730043240)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Sequelize

Sequelize 是一个基于承诺的 ORM，适用于 Node.js v4 及更高版本。这个 ORM 支持许多方言，比如：

+   `PostgreSQL`

+   `MySQL`

+   `SQLite`

+   `MSSQL`

这为事务提供了可靠的支持。使用 Sequelize，您可以使用`sequelize-typescript`，它提供了装饰器来放置在您的实体中，并管理模型的所有字段，带有类型和约束。

此外，Sequelize 来自许多钩子，为您提供了重要的优势，可以在事务的任何级别检查和操作数据。

在本章中，我们将看到如何使用`postgresql`配置您的数据库以及如何配置到您的数据库的连接。之后，我们将看到如何实现我们的第一个实体，这将是一个简单的`User`实体，然后如何为此实体创建一个提供者，以便将实体注入到`UserService`中。我们还将通过`umzug`看到迁移系统，以及如何创建我们的第一个迁移文件。

您可以查看存储库的`src/modules/database`，`src/modules/user`，`/src/shared/config`和`/src/migrations` `/migrate.ts`。

# 配置 Sequelize

为了能够使用 Sequelize，我们首先必须设置 sequelize 和我们的数据库之间的连接。为此，我们将创建`DatabaseModule`，其中将包含 sequelize 实例的提供者。

为了设置这个连接，我们将定义一个配置文件，其中将包含连接到数据库所需的所有属性。此配置将必须实现`IDatabaseConfig`接口，以避免忘记一些参数。

```js
export interface IDatabaseConfigAttributes {
    username: string;
    password: string;
    database: string;
    host: string;
    port: number;
    dialect: string;
    logging: boolean | (() => void);
    force: boolean;
    timezone: string;
}

export interface IDatabaseConfig {
    development: IDatabaseConfigAttributes;
}

```

此配置应该设置为以下示例，并通过环境变量或默认值设置参数。

```js
export const databaseConfig: IDatabaseConfig = {
    development: {
        username: process.env.POSTGRES_USER ||             'postgres',
        password: process.env.POSTGRES_PASSWORD || null,
        database: process.env.POSTGRES_DB || 'postgres',
        host: process.env.DB_HOST || '127.0.0.1',
        port: Number(process.env.POSTGRES_PORT) || 5432,
        dialect: 'postgres',
        logging: false,
        force: true,
        timezone: '+02:00',
    }
};

```

配置完成后，您必须创建适当的提供者，其目的是使用正确的配置创建 sequelize 实例。在我们的情况下，我们只是设置了环境配置，但您可以使用相同的模式设置所有配置，只需要更改值。

这个实例是让你了解应该提供的不同模型。为了告诉 sequelize 我们需要哪个模型，我们在实例上使用`addModels`方法，并传递一个模型数组。当然，在接下来的部分中，我们将看到如何实现一个新模型。

```js
export const databaseProvider = {
    provide: 'SequelizeInstance',
    useFactory: async () => {
        let config;
        switch (process.env.NODE_ENV) {
            case 'prod':
            case 'production':
            case 'dev':
            case 'development':
            default:
                config = databaseConfig.development;
        }

        const sequelize = new Sequelize(config);
        sequelize.addModels([User]);
        return sequelize;
    }
};

```

此提供者将返回 Sequelize 的实例。这个实例将有助于使用 Sequelize 提供的事务。此外，为了能够注入它，我们在`provide`参数中提供了令牌`SequelizeInstance`的名称，这将用于注入它。

Sequelize 还提供了一种立即同步模型和数据库的方法，使用`sequelize.sync()`。这种同步不应该在生产模式下使用，因为它每次都会重新创建一个新的数据库并删除所有数据。

我们现在已经设置好了我们的 Sequelize 配置，并且需要设置`DatabaseModule`，如下例所示：

```js
@Global()
@Module({
    providers: [databaseProvider],
    exports: [databaseProvider],
})
export class DatabaseModule {}

```

我们将`DatabaseModule`定义为`Global`，以便将其添加到所有模块作为相关模块，让您可以将提供者`SequelizeInstance`注入到任何模块中，如下所示：

```js
@Inject('SequelizeInstance`) private readonly sequelizeInstance

```

我们现在有一个完整的工作模块来访问我们数据库中的数据。

# 创建一个模型

设置好 sequelize 连接后，我们必须实现我们的模型。如前一节所示，我们告诉 Sequelize 我们将使用此方法`sequelize.addModels([User]);`来拥有`User`模型。

您现在看到了设置它所需的所有功能。

## @Table

这个装饰器将允许您配置我们对数据的表示，以下是一些参数：

```js
{

    timestamps:  true,
    paranoid:  true,
    underscored:  false,
    freezeTableName:  true,
    tableName:  'my_very_custom_table_name'
}

```

`timestamp`参数将告诉你想要有`updatedAt`和`deletedAt`列。`paranoid`参数允许你软删除数据而不是删除它以避免丢失数据。如果你传递`true`，Sequelize 将期望有一个`deletedAt`列以设置删除操作的日期。

`underscored`参数将自动将所有驼峰命名的列转换为下划线命名的列。

`freezTableName`将提供一种避免 Sequelize 将表名变为复数形式的方法。

`tableName`允许你设置表的名称。

在我们的案例中，我们只使用`timestamp: true, tableName: 'users'`来获取`updatedAt`和`createdAt`列，并将表命名为`users`。

## @column

这个装饰器将帮助定义我们的列。你也可以不传递任何参数，这样 Sequelize 将尝试推断列类型。可以推断的类型包括`string`、`boolean`、`number`、`Date`和`Blob`。

一些参数允许我们在列上定义一些约束。比如，假设`email`列，我们希望这个电子邮件是一个字符串，并且不能为空，所以这个电子邮件必须是唯一的。Sequelize 可以识别电子邮件，但我们必须告诉它如何验证电子邮件，通过传递`validate#isUnique`方法。

看一下下面的例子。

```js
@Column({
    type: DataType.STRING,
    allowNull: false,
    validate: {
        isEmail: true,
        isUnique: async (value: string, next: any): Promise<any> => {
            const isExist = await User.findOne({ where: { email: value }});
            if (isExist) {
                const error = new Error('The email is already used.');
                next(error);
            }
            next();
        },
    },
})

```

在前面的示例中，我们传递了一些选项，但我们也可以使用一些装饰器，如`@AllowNull(value: boolean)`，`@Unique`甚至`@Default(value: any)`。

为了设置一个`id`列，`@PrimaryKey`和`@AutoIncrement`装饰器是设置约束的一种简单方法。

## 创建用户模型

现在我们已经看到了一些有用的装饰器，让我们创建我们的第一个模型，`User`。为了做到这一点，我们将创建一个类，该类必须扩展自基类`Model<T>`，这个类需要为自身的模板值。

```js
export class User extends Model<User> {...}

```

现在我们添加了`@Table()`装饰器来配置我们的模型。这个装饰器接受与接口`DefineOptions`对应的选项，正如我们在***@Table 部分***中描述的，我们将传递 timestamp 为 true 和表的名称作为选项。

```js
@Table({ timestamp: true, tableName: 'users' } as IDefineOptions)
export class User extends Model<User> {...}

```

现在我们需要为我们的模型定义一些列。为此，`sequelize-typescript`提供了`@Column()`装饰器。这个装饰器允许我们提供一些选项来配置我们的字段。你可以直接传递数据类型`DataType.Type`。

```js
@Column(DataTypes.STRING)
public email: string;

```

你还可以使用***@Column 部分***中显示的选项来验证和确保电子邮件的数据。

```js
@Column({
    type: DataType.STRING,
    allowNull: false,
    validate: {
        isEmail: true,
        isUnique: async (value: string, next: any): Promise<any> => {
            const isExist = await User.findOne({
                where: { email: value }
            });
            if (isExist) {
                const error = new Error('The email is already used.');
                next(error);
            }
            next();
        },
    },
})
public email: string;

```

现在你知道如何设置列，让我们为简单的用户设置模型的其余部分。

```js
@Table(tableOptions)
export class User extends Model<User> {
    @PrimaryKey
    @AutoIncrement @Column(DataType.BIGINT)
    public id: number;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    public firstName: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
    })
    public lastName: string;

    @Column({
        type: DataType.STRING,
        allowNull: false,
        validate: {
            isEmail: true,
            isUnique: async (value: string, next: any): Promise<any> => {
                const isExist = await User.findOne({
                    where: { email: value }
                });
                if (isExist) {
                    const error = new Error('The email is already used.');
                    next(error);
                }
                next();
            },
        },
    })
    public email: string;

    @Column({
        type: DataType.TEXT,
        allowNull: false,
    })
    public password: string;

    @CreatedAt
    public createdAt: Date;

    @UpdatedAt
    public updatedAt: Date;

    @DeletedAt
    public deletedAt: Date;
}

```

在所有添加的列中，你可以看到`TEXT`类型的密码，但当然，你不能将密码存储为明文，所以我们必须对其进行哈希处理以保护它。为此，使用 Sequelize 提供的生命周期钩子。

## 生命周期钩子

Sequelize 提供了许多生命周期钩子，允许你在创建、更新或删除数据的过程中操作和检查数据。

以下是 Sequelize 中一些有用的钩子。

```js
  beforeBulkCreate(instances, options)
  beforeBulkDestroy(options)
  beforeBulkUpdate(options)

  beforeValidate(instance, options)
  afterValidate(instance, options)

  beforeCreate(instance, options)
  beforeDestroy(instance, options)
  beforeUpdate(instance, options)
  beforeSave(instance, options)
  beforeUpsert(values, options)

  afterCreate(instance, options)
  afterDestroy(instance, options)
  afterUpdate(instance, options)
  afterSave(instance, options)
  afterUpsert(created, options)

  afterBulkCreate(instances, options)
  afterBulkDestroy(options)
  afterBulkUpdate(options)

```

在这种情况下，我们需要使用`@BeforeCreate`装饰器来对密码进行哈希处理，并在存储到数据库之前替换原始值。

```js
@Table(tableOptions)
export class User extends Model<User> {
    ...
    @BeforeCreate
    public static async hashPassword(user: User, options: any) {
        if (!options.transaction) throw new Error('Missing transaction.');

        user.password = crypto.createHmac('sha256', user.password).digest('hex');
    }
}

```

之前写的`BeforeCreate`允许你在将对象插入到数据库之前覆盖用户的`password`属性值，并确保最低限度的安全性。

# 将模型注入到服务中

我们的第一个`User`模型现在已经设置好了。当然，我们需要将其注入到服务或甚至控制器中。要在任何其他地方注入模型，我们必须首先创建适当的提供者，以便将其提供给模块。

这个提供者将定义用于注入的密钥，并将`User`模型作为值，我们之前已经实现了这个模型。

```js
export const userProvider = {
    provide: 'UserRepository',
    useValue: User
};

```

要将其注入到服务中，我们将使用`@Inject()`装饰器，它可以使用前面示例中定义的字符串`UserRepository`。

```js
@Injectable()
export class UserService implements IUserService {
    constructor(@Inject('UserRepository') private readonly UserRepository: typeof User) { }
    ...
}

```

在将模型注入服务之后，您可以使用它来访问和操作数据。例如，您可以执行`this.UserRepository.findAll()`来在数据库中注册数据。

最后，我们必须设置模块以将`userProvider`作为提供者，该提供者提供对模型和`UserService`的访问。`UserService`可以导出，以便在另一个模块中使用，通过导入`UserModule`。

```js
@Module({
    imports: [],
    providers: [userProvider, UserService],
    exports: [UserService]
})
export class UserModule {}

```

# 使用 Sequelize 事务

您可能会注意到这行代码，`if (!options.transaction) throw new Error('Missing transaction.');`，在使用`@BeforeCreate`装饰的`hashPassword`方法中。如前所述，Sequelize 提供了对事务的强大支持。因此，对于每个操作或操作过程，您都可以使用事务。要使用 Sequelize 事务，请查看以下`UserService`的示例。

```js
@Injectable()
export class UserService implements IUserService {
    constructor(@Inject('UserRepository') private readonly UserRepository: typeof User,
                @Inject('SequelizeInstance') private readonly sequelizeInstance) { }
    ...
}

```

我们在本章中提到的模型和 Sequelize 实例都已注入。

要使用事务来包装对数据库的访问，您可以执行以下操作：

```js
public async create(user: IUser): Promise<User> {
    return await this.sequelizeInstance.transaction(async transaction => {
        return await this.UserRepository.create<User>(user, {
            returning: true,
            transaction,
        });
    });
}

```

我们使用`sequelizeInstance`创建一个新的事务，并将其传递给`UserRepository`的`create`方法。

# 迁移

使用 Sequelize，您可以同步模型和数据库。问题是，此同步将删除所有数据，以便重新创建表示模型的所有表。因此，此功能在测试中很有用，但在生产模式下则不适用。

为了操作数据库，您可以使用`umzung`，这是一个与框架无关的库和迁移工具，适用于 Nodejs。它与任何数据库都无关，但提供了一个 API，用于迁移或回滚迁移。

当您使用命令`npm run migrate up`时，它会执行`ts-node migrate.ts`，您可以将`up/down`作为参数传递。为了跟踪已应用的所有迁移，将创建一个名为`SequelizeMeta`的新表，并将所有已应用的迁移存储在此表中。

我们的迁移文件可以在存储库中找到，名称为`migrate.ts`。此外，所有迁移文件将存储在存储库示例的`migrations`文件夹中。

## 配置迁移脚本

为了配置 umzung 实例，您可以设置一些选项：

+   `storage`，对应于我们的`sequelize`字符串键

+   `storageOptions`，它将使用 Sequelize，并且您可以在此选项中更改用于存储已应用迁移的名称的列的默认名称`modelName`，`tableName`和`columnName`属性。

还可以进行其他一些配置，以设置`up`方法名称和`down`方法名称，传递日志函数。`migrations`属性将允许您提供一些参数以传递给 up/down 方法，并提供要应用的迁移的路径以及适当的模式。

```js
const umzug = new Umzug({
    storage: 'sequelize',
    storageOptions: { sequelize },

    migrations: {
        params: [
            sequelize,
            sequelize.constructor, // DataTypes
        ],
        path: './migrations',
        pattern: /\.ts$/
    },

    logging: function () {
        console.log.apply(null, arguments);
    }
});

```

## 创建迁移

要执行迁移脚本，请提供要应用的迁移。假设您想使用迁移创建`users`表。您必须设置`up`和`down`方法。

```js
export async function up(sequelize) {
    // language=PostgreSQL
    sequelize.query(`
        CREATE TABLE "users" (
            "id" SERIAL UNIQUE PRIMARY KEY NOT NULL,
            "firstName" VARCHAR(30) NOT NULL,
            "lastName" VARCHAR(30) NOT NULL,
            "email" VARCHAR(100) UNIQUE NOT NULL,
            "password" TEXT NOT NULL,
            "birthday" TIMESTAMP,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL,
            "deletedAt" TIMESTAMP
        );
    `);

    console.log('*Table users created!*');
}

export async function down(sequelize) {
    // language=PostgreSQL
    sequelize.query(`DROP TABLE users`);
}

```

在每个方法中，参数将是`sequelize`，这是配置文件中使用的实例。通过此实例，您可以使用查询方法来编写我们的 SQL 查询。在前面的示例中，函数`up`将执行查询以创建`users`表。`down`方法的目的是在回滚时删除此表。

# 总结

在本章中，您已经看到了如何通过实例化 Sequelize 实例来设置与数据库的连接，并使用工厂直接在另一个地方注入实例。

另外，您已经看到了 sequelize-typescript 提供的装饰器，以便设置一个新的模型。您还看到了如何在列上添加一些约束，以及如何在保存之前使用生命周期钩子来对密码进行哈希处理。当然，这些钩子可以用来验证一些数据或在执行其他操作之前检查一些信息。但您也已经看到了如何使用`@BeforeCreate`钩子。因此，您已经准备好使用 Sequelize 事务系统。

最后，您已经看到了如何配置 umzug 来执行迁移，并且如何创建您的第一个迁移以创建用户表。

在下一章中，您将学习如何使用 Mongoose。


# 第七章：Mongoose

Mongoose 是本书中将要介绍的第三个也是最后一个数据库映射工具。它是 JavaScript 世界中最知名的 MongoDB 映射工具。

# 关于 MongoDB 的一点说明

当 MongoDB 最初发布时，即 2009 年，它震惊了数据库世界。那时使用的绝大多数数据库都是关系型的，而 MongoDB 迅速成长为最受欢迎的非关系型数据库（也称为“NoSQL”）。

NoSQL 数据库与关系型数据库（如 MySQL、PostgreSQL 等）不同，它们以其他方式对存储的数据进行建模，而不是相互关联的表。

具体来说，MongoDB 是一种“面向文档的数据库”。它以 BSON 格式（“二进制 JSON”，一种包含特定于 MongoDB 的各种数据类型的 JSON 扩展）保存数据的“文档”。MongoDB 文档被分组在“集合”中。

传统的关系型数据库将数据分隔在表和列中，类似于电子表格。另一方面，面向文档的数据库将完整的数据对象存储在数据库的单个实例中，类似于文本文件。

虽然关系型数据库结构严格，但面向文档的数据库要灵活得多，因为开发人员可以自由使用非预定义的结构在我们的文档中，甚至可以完全改变我们的数据结构从一个文档实例到另一个文档实例。

这种灵活性和缺乏定义的结构意味着通常更容易更快地“映射”（转换）我们的对象以便将它们存储在数据库中。这为我们的项目带来了减少编码开销和更快迭代的好处。

# 关于 Mongoose 的一点说明

Mongoose 在技术上并不是 ORM（对象关系映射），尽管通常被称为是。相反，它是 ODM（对象文档映射），因为 MongoDB 本身是基于文档而不是关系表的。不过，ODM 和 ORM 的理念是相同的：提供一个易于使用的数据建模解决方案。

Mongoose 使用“模式”的概念。模式只是一个定义集合（一组文档）以及文档实例将具有的属性和允许的值类型的对象（即我们将称之为“它们的形状”）。

## Mongoose 和 Nest.js

就像我们在 TypeORM 和 Sequelize 章节中看到的一样，Nest.js 为我们提供了一个可以与 Mongoose 一起使用的模块。

# 入门

首先，我们需要安装 Mongoose npm 包，以及 Nest.js/Mongoose npm 包。

在控制台中运行`npm install --save mongoose @nestjs/mongoose`，然后立即运行`npm install --save-dev @types/mongoose`。

## 设置数据库

Docker Compose 是使用 MongoDB 最简单的方法。Docker 注册表中有一个官方的 MongoDB 镜像，我们建议您使用。目前写作本文时的最新稳定版本是`3.6.4`。

让我们创建一个 Docker Compose 文件来构建和启动我们将使用的数据库，以及我们的 Nest.js 应用，并将它们链接在一起，以便我们可以稍后从我们的代码中访问数据库。

```js
version: '3'

volumes:
  mongo_data:

services:
  mongo:
    image: mongo:latest
    ports:
    - "27017:27017"
    volumes:
    - mongo_data:/data/db
  api:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - NODE_ENV=development
    depends_on:
      - mongo
    links:
      - mongo
    environment:
      PORT: 3000
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules
    command: >
      npm run start:dev

```

我们指向 MongoDB 镜像的`latest`标签，这是一个解析为最新稳定版本的别名。如果您感到冒险，可以随意将标签更改为`unstable`...不过要注意可能会出现问题！

## 启动容器

现在您的 Docker Compose 文件已经准备好了，启动容器并开始工作吧！

在控制台中运行`docker-compose up`来执行。

## 连接到数据库

我们的本地 MongoDB 实例现在正在运行并准备好接受连接。

我们需要将几步前安装的 Nest.js/Mongoose 模块导入到我们的主应用模块中。

```js
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forRoot(),
    ...
  ],
})
export class AppModule {}

```

我们将`MongooseModule`添加到`AppModule`中，并且我们依赖`forRoot()`方法来正确注入依赖项。如果您阅读了关于 TypeORM 的章节，或者熟悉 Angular 及其官方路由模块，您可能会发现`forRoot()`方法很熟悉。

上面的代码有一个*验证码*：它不起作用，因为 Mongoose 或`MongooseModule`仍然无法找出*如何*连接到我们的 MongoDB 实例。

### 连接字符串

如果你查看 Mongoose 文档或在 Google 上快速搜索，你会发现连接到 MongoDB 实例的通常方法是使用`'mongodb://localhost/test'`字符串作为 Mongoose 的`.connect()`方法的参数（甚至在 Node MongoDB 原生客户端中）。

这个字符串就是所谓的“连接字符串”。连接字符串告诉任何 MongoDB 客户端如何连接到相应的 MongoDB 实例。

坏消息是，在我们的情况下，“默认”示例连接字符串将无法工作，因为我们正在运行我们的数据库实例，它在另一个容器中链接，一个 Node.js 容器，这是我们的代码运行的容器。

然而，好消息是，我们可以使用 Docker Compose 链接来连接到我们的数据库，因为 Docker Compose 在 MongoDB 容器和 Node.js 容器之间建立了虚拟网络连接。

所以，我们唯一需要做的就是将示例连接字符串更改为

`'mongodb://mongo:27017/nest'`

其中`mongo`是我们 MongoDB 容器的名称（我们在 Docker Compose 文件中指定了这一点），`27017`是 MongoDB 容器正在暴露的端口（27017 是 MongoDB 的默认端口），`nest`是我们将在其上存储我们的文档的集合（你可以自由地将其更改为你的喜好）。

### `forRoot()`方法的正确参数

现在我们已经调整了我们的连接字符串，让我们修改我们原来的`AppModule`导入。

```js
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://mongo:27017/nest'),
    ...
  ],
})
export class AppModule {}

```

现在连接字符串作为参数添加到`forRoot()`方法中，因此 Mongoose 知道*如何*连接到数据库实例并且将成功启动。

# 对我们的数据进行建模

我们之前已经提到 Mongoose 使用“模式”的概念。

Mongoose 模式扮演着与 TypeORM 实体类似的角色。然而，与后者不同，前者不是类，而是从 Mongoose 定义（和导出）的`Schema`原型继承的普通对象。

无论如何，当你准备使用它们时，模式需要被实例化为“模型”。我们喜欢把模式看作对象的“蓝图”，把“模型”看作对象工厂。

## 我们的第一个模式

说到这一点，让我们创建我们的第一个实体，我们将其命名为`Entry`。我们将使用这个实体来存储我们博客的条目（帖子）。我们将在`src/entries/entry.entity.ts`创建一个新文件；这样 TypeORM 将能够找到这个实体文件，因为在我们的配置中我们指定实体文件将遵循`src/**/*.entity.ts`文件命名约定。

让我们创建我们的第一个模式。我们将把它用作存储我们博客条目的蓝图。我们还将把模式放在其他博客条目相关文件旁边，通过“域”（即功能）对我们的文件进行分组。

**注意：**你可以根据自己的喜好组织模式。我们（以及官方的 Nest.js 文档）建议将它们存储在你使用每一个模式的模块附近。无论如何，只要在需要时正确导入模式文件，你应该可以使用任何其他结构方法。

**`src/entries/entry.schema.ts`**

```js
import { Schema } from 'mongoose';

export const EntrySchema = new mongoose.Schema({
  _id: Schema.Types.ObjectId,
  title: String,
  body: String,
  image: String,
  created_at: Date,
});

```

我们刚刚编写的模式是：

1.  创建一个具有我们博客条目所需属性的对象。

1.  实例化一个新的`mongoose.Schema`类型对象。

1.  将我们的对象传递给`mongoose.Schema`类型对象的构造函数。

1.  导出实例化的`mongoose.Schema`，以便可以在其他地方使用。

**注意：**在一个名为`_id`的属性中存储我们对象的 ID，以下划线开头，这是在使用 Mongoose 时一个有用的约定；它将使得后来能够依赖于 Mongoose 的`.findById()`模型方法。

### 将模式包含到模块中

下一步是“通知”Nest.js`MongooseModule`，你打算使用我们创建的新模式。为此，我们需要创建一个“Entry”模块（如果我们还没有的话），如下所示：

**`src/entries/entries.module.ts`**

```js
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { EntrySchema } from './entry.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'Entry', schema: EntrySchema }]),
  ],
})
export class EntriesModule {}

```

与我们在 TypeORM 章节中所做的非常相似，现在我们需要使用`MongooseModule`的`forFeature()`方法来定义它需要注册的模式，以便在模块范围内使用模型。

再次强调，这种方法受到 Angular 模块的影响，比如路由器，所以这可能对你来说很熟悉！

如果不是，请注意，这种处理依赖关系的方式极大地增加了应用程序中功能模块之间的解耦，使我们能够通过将模块添加或删除到主`AppModule`的导入中轻松地包含、删除和重用功能和功能。

### 将新模块包含到主模块中

另外，在谈到`AppModule`时，不要忘记将新的`EntriesModule`导入到根`AppModule`中，这样我们就可以成功地使用我们为博客编写的新功能。现在让我们来做吧！

```js
import { MongooseModule } from '@nestjs/mongoose';

import { EntriesModule } from './entries/entries.module';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://mongo:27017/nest'),
    EntriesModule,
    ...
  ],
})
export class AppModule {}

```

# 使用模式

如前所述，我们将使用我们刚刚定义的模式来实例化一个新的数据模型，我们将能够在我们的代码中使用它。 Mongoose 模型是将对象映射到数据库文档的重要工具，并且还抽象了操作数据的常见方法，比如`.find()`和`.save()`。

如果你来自 TypeORM 章节，Mongoose 中的模型与 TypeORM 中的存储库非常相似。

在必须将请求连接到数据模型时，Nest.js 中的典型方法是构建专用服务，这些服务作为与每个模型的“触点”，以及控制器。这将服务与到达 API 的请求联系起来。我们将在以下步骤中遵循`数据模型->服务->控制器`的方法。

## 接口

在创建服务和控制器之前，我们需要为我们的博客条目编写一个小接口。这是因为，如前所述，Mongoose 模式不是 TypeScript 类，因此为了正确地对对象进行类型定义以便以后使用，我们需要首先为其定义一个类型。

**`src/entries/entry.interface.ts`**

```js
import { Document } from 'mongoose';

export interface Entry extends Document {
  readonly _id: string;
  readonly title: string;
  readonly body: string;
  readonly image: string;
  readonly created_at: Date;
}

```

记住要保持接口与模式同步，这样你就不会在以后的对象形状问题上遇到问题。

## 服务

让我们为我们的博客条目创建一个服务，与`Entry`模型交互。

**`src/entries/entries.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';

import { EntrySchema } from './entry.schema';
import { Entry } from './entry.interface';

@Injectable()
export class EntriesService {
  constructor(
    @InjectModel(EntrySchema) private readonly entryModel: Model<Entry>
  ) {}

  // this method retrieves all entries
  findAll() {
    return this.entryModel.find().exec();
  }

  // this method retrieves only one entry, by entry ID
  findById(id: string) {
    return this.entryModel.findById(id).exec();
  }

  // this method saves an entry in the database
  create(entry) {
    entry._id = new Types.ObjectId();
    const createdEntry = new this.entryModel(entry);
    return createdEntry.save();
  }
}

```

在上面的代码中，最重要的部分发生在构造函数内部：我们使用`@InjectModel()`装饰器来实例化我们的模型，通过将期望的模式（在本例中为`EntrySchema`）作为装饰器参数传递。

然后，在同一行代码中，我们将模型作为服务中的依赖项注入，将其命名为`entryModel`并为其分配一个`Model`类型；从这一点开始，我们可以利用 Mongoose 模型为文档进行抽象、简化的操作提供的所有好处。

另一方面，值得一提的是，在`create()`方法中，我们通过使用`_id`属性（正如我们之前在模式中定义的）向接收到的条目对象添加一个 ID，并使用 Mongoose 内置的`Types.ObjectId()`方法生成一个值。

## 控制器

我们需要覆盖模型->服务->控制器链中的最后一步。控制器将使得可以向 Nest.js 应用程序发出 API 请求，并且可以从数据库中写入或读取数据。

这就是我们的控制器应该看起来的样子：

**`src/entries/entries.controller.ts`**

```js
import { Controller, Get, Post, Body, Param } from '@nestjs/common';

import { EntriesService } from './entry.service';

@Controller('entries')
export class EntriesController {
  constructor(private readonly entriesSrv: EntriesService) {}

  @Get()
  findAll() {
    return this.entriesSrv.findAll();
  }

  @Get(':entryId')
  findById(@Param('entryId') entryId) {
    return this.entriesSrv.findById(entryId);
  }

  @Post()
  create(@Body() entry) {
    return this.entriesSrv.create(entry);
  }
}

```

像往常一样，我们正在使用 Nest.js 依赖注入，使`EntryService`在我们的`EntryController`中可用。然后，我们将我们期望监听的三个基本请求（`GET`所有条目，`GET`按 ID 获取一个条目和`POST`一个新条目）路由到我们服务中的相应方法。

# 第一个请求

此时，我们的 Nest.js API 已经准备好接收请求（包括`GET`和`POST`），并根据这些请求在我们的 MongoDB 实例中操作数据。换句话说，我们已经准备好从 API 中读取并向数据库写入数据。

让我们试一试。

我们将从对`/entries`端点的 GET 请求开始。显然，由于我们还没有创建任何条目，所以我们应该收到一个空数组作为响应。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
< HTTP/1.1 200 OK

[]

```

让我们通过向`entries`端点发送`POST`请求并在请求体中包含一个与我们之前定义的`EntrySchema`形状匹配的 JSON 对象来创建一个新条目。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
| {
|   "title": "This is our first post",
|   "body": "Bla bla bla bla bla",
|   "image": "http://lorempixel.com/400",
|   "created_at": "2018-04-15T17:42:13.911Z"
| }

< HTTP/1.1 201 Created

```

是的！我们之前的`POST`请求触发了数据库中的写入。让我们再次尝试检索所有条目。

```js
> GET /entries HTTP/1.1
> Host: localhost:3000
< HTTP/1.1 200 OK

[{
  "id": 1,
  "title": "This is our first post",
  "body": "Bla bla bla bla bla",
  "image": "http://lorempixel.com/400",
  "created_at": "2018-04-15T17:42:13.911Z"
}]

```

我们刚刚确认对我们的`/entries`端点的请求成功执行了数据库中的读写操作。这意味着我们的 Nest.js 应用现在可以使用，因为几乎任何服务器应用程序的基本功能（即存储数据并根据需要检索数据）都正常工作。

# 关系

虽然 MongoDB 不是关系数据库，但它允许进行“类似于连接”的操作，以一次检索两个（或更多）相关文档。

幸运的是，Mongoose 包含了一层抽象，允许我们以清晰、简洁的方式在对象之间建立关系。这是通过在模式属性中使用`ref`以及`.populate()`方法（触发所谓的“填充”过程的方法）来实现的；稍后会详细介绍。

## 建模关系

让我们回到我们的博客示例。记住到目前为止我们只有一个定义博客条目的模式。我们将创建一个第二个模式，它将允许我们为每个博客条目创建评论，并以一种允许我们稍后检索博客条目以及属于它的评论的方式保存到数据库中，所有这些都可以在单个数据库操作中完成。

因此，首先，我们创建一个像下面这样的`CommentSchema`：

**`src/comments/comment.schema.ts`**

```js
import * as mongoose from 'mongoose';

export const CommentSchema = new mongoose.Schema({
  _id: Schema.Types.ObjectId,
  body: String,
  created_at: Date,
  entry: { type: Schema.Types.ObjectId, ref: 'Entry' },
});

```

在这一点上，这个模式是我们之前的`EntrySchema`的“精简版本”。实际上，它是由预期的功能决定的，所以我们不应该太在意这个事实。

再次，我们依赖于名为`_id`的属性作为命名约定。

一个值得注意的新东西是`entry`属性。它将用于存储每个评论所属的条目的引用。`ref`选项告诉 Mongoose 在填充期间使用哪个模型，我们的情况下是`Entry`模型。我们在这里存储的所有`_id`都需要是 Entry 模型的文档`_id`。

**注意：** 为了简洁起见，我们将忽略`Comment`接口；这对你来说应该足够简单。不要忘记完成它！

其次，我们需要更新我们原始的`EntrySchema`，以便允许我们保存属于每个条目的`Comment`实例的引用。看下面的示例如何做到这一点：

**`src/entries/entry.schema.ts`**

```js
import * as mongoose from 'mongoose';

export const EntrySchema = new mongoose.Schema({
  _id: Schema.Types.ObjectId,
  title: String,
  body: String,
  image: String,
  created_at: Date,
  comments: [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
});

```

请注意，我们刚刚添加的`comments`属性是*对象数组*，每个对象都有一个 ObjectId 以及一个引用。关键在于包含*相关对象*的数组，因为这个数组使我们可以称之为“一对多”关系，如果我们处于关系数据库的上下文中。

换句话说，每个条目可以有多个评论，但每个评论只能属于一个条目。

## 保存关系

一旦我们的关系被建模，我们需要提供一个方法将它们保存到我们的 MongoDB 实例中。

在使用 Mongoose 时，存储模型实例及其相关实例需要一定程度的手动嵌套方法。幸运的是，`async/await`将使任务变得更加容易。

让我们修改我们的`EntryService`，以保存接收到的博客条目和与之关联的评论；两者将作为不同的对象发送到`POST`端点。

**`src/entries/entries.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';

import { EntrySchema } from './entry.schema';
import { Entry } from './entry.interface';

import { CommentSchema } from './comment.schema';
import { Comment } from './comment.interface';

@Injectable()
export class EntriesService {
  constructor(
    @InjectModel(EntrySchema) private readonly entryModel: Model<Entry>,
    @InjectModel(CommentSchema) private readonly commentModel: Model<Comment>
  ) {}

  // this method retrieves all entries
  findAll() {
    return this.entryModel.find().exec();
  }

  // this method retrieves only one entry, by entry ID
  findById(id: string) {
    return this.entryModel.findById(id).exec();
  }

  // this method saves an entry and a related comment in the database
  async create(input) {
    const { entry, comment } = input;

    // let's first take care of the entry (the owner of the relationship)
    entry._id = new Types.ObjectId();
    const entryToSave = new this.entryModel(entry);
    await entryToSave.save();

    // now we are ready to handle the comment
    // this is how we store in the comment the reference
    // to the entry it belongs to
    comment.entry = entryToSave._id;

    comment._id = new Types.ObjectId();
    const commentToSave = new this.commentModel(comment);
    commentToSave.save();

    return { success: true };
  }
}

```

修改后的`create()`方法现在是：

1.  为条目分配一个 ID。

1.  将条目保存并分配给`const`。

1.  为评论分配一个 ID。

1.  使用我们之前创建的条目的 ID 作为评论的`entry`属性的值。*这是我们之前提到的引用。*

1.  保存评论。

1.  返回成功状态消息。

通过这种方式，我们确保在评论中成功存储了对评论所属的条目的引用。顺便说一句，注意我们通过条目的 ID 来存储引用。

显然，下一步应该是提供一种从数据库中读取我们现在能够保存到其中的相关项目的方法。

## 阅读关系

正如前面几节所介绍的，Mongoose 提供的从数据库一次检索相关文档的方法称为“population”，并且通过内置的`.populate()`方法调用它。

我们将看到如何通过再次更改`EntryService`来使用这种方法；在这一点上，我们将处理`findById()`方法。

**`src/entries/entries.service.ts`**

```js
import { Component } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';

import { EntrySchema } from './entry.schema';
import { Entry } from './entry.interface';

import { CommentSchema } from './comment.schema';
import { Comment } from './comment.interface';

@Injectable()
export class EntriesService {
  constructor(
    @InjectModel(EntrySchema) private readonly entryModel: Model<Entry>,
    @InjectModel(CommentSchema) private readonly commentModel: Model<Comment>
  ) {}

  // this method retrieves all entries
  findAll() {
    return this.entryModel.find().exec();
  }

  // this method retrieves only one entry, by entry ID,
  // including its related documents with the "comments" reference
  findById(id: string) {
    return this.entryModel
      .findById(id)
      .populate('comments')
      .exec();
  }

  // this method saves an entry and a related comment in the database
  async create(input) {
    ...
  }
}

```

我们刚刚包含的`.populate('comments')`方法将把`comments`属性值从 ID 数组转换为与这些 ID 对应的实际文档数组。换句话说，它们的 ID 值被替换为通过执行单独查询从数据库返回的 Mongoose 文档。

# 摘要

NoSQL 数据库是“传统”关系数据库的一个强大替代品。MongoDB 可以说是当今使用的 NoSQL 数据库中最知名的，它使用 JSON 变体编码的文档。使用诸如 MongoDB 之类的基于文档的数据库允许开发人员使用更灵活、松散结构的数据模型，并可以提高在快速移动的项目中的迭代时间。

著名的 Mongoose 库是一个适配器，用于在 Node.js 中使用 MongoDB，并在查询和保存操作时抽象了相当多的复杂性。

在本章中，我们涵盖了与 Mongoose 和 Nest.js 一起工作的许多方面，比如：

+   如何使用 Docker Compose 启动本地 MongoDB 实例。

+   如何在我们的根模块中导入@nestjs/mongoose 模块并连接到我们的 MongoDb 实例。

+   什么是模式，以及如何为建模我们的数据创建一个模式。

+   建立一个管道，使我们能够以对 Nest.js 端点发出的请求的反应来写入和读取我们的 MongoDB 数据库。

+   如何在不同类型的 MongoDB 文档之间建立关系，以及如何以有效的方式存储和检索这些关系。

在下一章中，我们将介绍 Web 套接字。


# 第八章：Web 套接字

正如您所见，Nest.js 通过`@nestjs/websockets`包提供了一种在应用程序中使用 Web 套接字的方法。此外，在框架内使用`Adapter`允许您实现所需的套接字库。默认情况下，Nest.js 自带适配器，允许您使用`socket.io`，这是一个众所周知的 Web 套接字库。

您可以创建一个完整的 Web 套接字应用程序，还可以在您的 Rest API 中添加一些 Web 套接字功能。在本章中，我们将看到如何使用 Nest.js 提供的装饰器实现在 Rest API 上使用 Web 套接字，以及如何使用特定中间件验证经过身份验证的用户。

Web 套接字的优势在于能够根据您的需求在应用程序中具有一些实时功能。对于本章，您可以查看存储库中的`/src/gateways`文件，还有`/src/shared/adapters`和`/src/middlewares`。

想象一下以下`CommentGatewayModule`，它看起来像这样：

```js
@Module({
    imports: [UserModule, CommentModule],
    providers: [CommentGateway]
})
export class CommentGatewayModule { }

```

导入`UserModule`以便访问`UserService`，这将在以后很有用，以及`CommentModule`。当然，我们将创建`CommentGateway`，它将用作可注入服务。

# WebSocketGateway

要使用 Nest.js Web 套接字实现您的第一个模块，您必须使用`@WebSocketGateway`装饰器。此装饰器可以接受一个对象作为参数，以提供配置如何使用适配器的方法。

参数的实现遵守`GatewayMetadata`接口，允许您提供：

+   `port`，适配器必须使用的端口

+   `namespace`，属于处理程序

+   在访问处理程序之前必须应用的`middlewares`

所有参数都是可选的。

要使用它，您必须创建您的第一个网关类，因此想象一个`UserGateway`：

```js
@WebSocketGateway({
    middlewares: [AuthenticationGatewayMiddleware]
})  
export class UserGateway { /*....*/ }

```

默认情况下，没有任何参数，套接字将使用与您的 express 服务器相同的端口（通常为`3000`）。正如您所见，在前面的示例中，我们使用了`@WebSocketGateway`，它使用默认端口`3000`，没有命名空间，并且有一个稍后将看到的中间件。

# 网关

在先前看到的装饰器中使用的类中的网关包含您需要提供事件结果的所有处理程序。

Nest.js 带有一个装饰器，允许您访问服务器实例`@WebSocketServer`。您必须在类的属性上使用它。

```js
export class CommentGateway {  
    @WebSocketServer() server; 

    /* ... */
}

```

此外，在整个网关中，您可以访问可注入服务。因此，为了访问评论数据，注入由`CommentModule`导出的`CommentService`，该服务已被注入到此模块中。

```js
export class CommentGateway {
    /* ... */

    constructor(private readonly commentService: CommentService) { }

    /* ... */
}

```

评论服务允许您为下一个处理程序返回适当的结果。

```js
export class CommentGateway {
    /* ... */

    @SubscribeMessage('indexComment')
    async index(client, data): Promise<WsResponse<any>> {
        if (!data.entryId) throw new WsException('Missing entry id.');

        const comments = await this.commentService.findAll({
            where: {entryId: data.entryId}
        });

        return { event: 'indexComment', data: comments };
    }

    @SubscribeMessage('showComment')
    async show(client, data): Promise<WsResponse<any>> {
        if (!data.entryId) throw new WsException('Missing entry id.');
        if (!data.commentId) throw new WsException('Missing comment id.');

        const comment = await this.commentService.findOne({
            where: {
                id: data.commentId,
                entryId: data.entryId
            }
        });

        return { event: 'showComment', data: comment };
    }
}

```

现在我们有两个处理程序，`indexComment`和`showComment`。要使用`indexComment`处理程序，我们期望有一个`entryId`以提供适当的评论，而对于`showComment`，我们期望有一个`entryId`，当然还有一个`commentId`。

正如您所见，要创建事件处理程序，请使用框架提供的`@SubscribeMessage`装饰器。此装饰器将使用传递的字符串作为参数创建`socket.on(event)`，其中事件对应于事件。

# 认证

我们已经设置了我们的`CommentModule`，现在我们想使用令牌对用户进行身份验证（请查看认证章节）。在此示例中，我们使用一个共享服务器用于 REST API 和 Web 套接字事件处理程序。因此，我们将共享身份验证令牌，以查看如何验证用户登录应用程序后收到的令牌。

重要的是要保护 Web 套接字，以避免在未登录应用程序的情况下访问数据。

如前一部分所示，我们使用了名为`AuthenticationGatewayMiddleware`的中间件。此中间件的目的是从 Web 套接字`query`中获取令牌，该令牌带有`auth_token`属性。

如果未提供令牌，中间件将返回`WsException`，否则我们将使用`jsonwebtoken`库（请查看身份验证章节）来验证令牌。

让我们设置中间件：

```js
@Injectable()
export class AuthenticationGatewayMiddleware implements GatewayMiddleware {
    constructor(private readonly userService: UserService) { }
    resolve() {
        return (socket, next) => {
            if (!socket.handshake.query.auth_token) {
                throw new WsException('Missing token.');
            }

            return jwt.verify(socket.handshake.query.auth_token, 'secret', async (err, payload) => {
                if (err) throw new WsException(err);

                const user = await this.userService.findOne({ where: { email: payload.email }});
                socket.handshake.user = user;
                return next();
            });
        }
    }
}

```

用于 Web 套接字的中间件与 REST API 几乎相同。现在实现`GatewayMiddleware`接口与`resolve`函数几乎相同。不同之处在于，您必须返回一个函数，该函数以`socket`和`next`函数作为其参数。套接字包含客户端发送的`query`的`handshake`和所有提供的参数，我们的情况下是`auth_token`。

与经典的身份验证中间件类似（请查看身份验证章节），套接字将尝试使用给定的有效负载查找用户，其中包含电子邮件，然后在握手中注册用户，以便在网关处理程序中访问。这是一种灵活的方式，可以在不再在数据库中查找的情况下已经拥有用户。

# 适配器

正如本章开头所提到的，Nest.js 自带了自己的适配器，使用`socket.io`。但是框架需要灵活，可以与任何第三方库一起使用。为了提供实现另一个库的方法，您可以创建自己的适配器。

适配器必须实现`WebSocketAdapter`接口，以实现以下方法。例如，我们将在新的适配器中使用`ws`作为套接字库。为了使用它，我们将不得不将`app`注入到构造函数中，如下所示：

```js
export class WsAdapter implements WebSocketAdapter {
    constructor(private app: INestApplication) { }

    /* ... */
}

```

通过这样做，我们可以获取`httpServer`以便与`ws`一起使用。之后，我们必须实现`create`方法以创建套接字服务器。

```js
export class WsAdapter implements WebSocketAdapter {
    /* ... */

    create(port: number) {
        return new WebSocket.Server({
            server: this.app.getHttpServer(),
            verifyClient: ({ origin, secure, req }, next) => { 
                return (new WsAuthenticationGatewayMiddleware(this.app.select(UserModule).
                get(UserService))).resolve()(req, next);
            }
        });
    }   

    /* ... */
}

```

如您所见，我们实现了`verifyClient`属性，该属性接受一个带有`{ origin, secure, req }`和`next`值的方法。我们将使用`req`，即来自客户端的`IncomingMessage`和`next`方法，以便继续该过程。我们使用`WsAuthenticationGatewayMiddleware`来验证客户端的令牌，并注入适当的依赖项，选择正确的模块和正确的服务。

在这种情况下，中间件处理身份验证：

```js
@Injectable()
export class WsAuthenticationGatewayMiddleware implements GatewayMiddleware {
    constructor(private userService: UserService) { }
    resolve() {
        return (req, next) => {
            const matches = req.url.match(/token=([^&].*)/);
            req['token'] = matches && matches[1];

            if (!req.token) {
                throw new WsException('Missing token.');
            }

            return jwt.verify(req.token, 'secret', async (err, payload) => {
                if (err) throw new WsException(err);

                const user = await this.userService.findOne({ where: { email: payload.email }});
                req.user = user;
                return next(true);
            });
        }
    }
}

```

在这个中间件中，我们必须手动解析 URL 以获取令牌，并使用`jsonwebtoken`进行验证。之后，我们必须实现`bindClientConnect`方法，将连接事件绑定到 Nest.js 将使用的回调方法。这是一个简单的方法，它接受服务器的参数和回调方法。

```js
export class WsAdapter implements WebSocketAdapter {
    /* ... */

    bindClientConnect(server, callback: (...args: any[]) => void) {
        server.on('connection', callback);
    }

    /* ... */
}

```

要完成我们的新自定义适配器，实现`bindMessageHandlers`以将事件和数据重定向到网关的适当处理程序。该方法将使用`bindMessageHandler`来执行处理程序并将结果返回给`bindMessageHandlers`方法，后者将结果返回给客户端。

```js
export class WsAdapter implements WebSocketAdapter {
    /* ... */

        bindMessageHandlers(client: WebSocket, handlers: MessageMappingProperties[], process: (data) => Observable<any>) {
            Observable.fromEvent(client, 'message')
                .switchMap((buffer) => this.bindMessageHandler(buffer, handlers, process))
                .filter((result) => !!result)
                .subscribe((response) => client.send(JSON.stringify(response)));
        }

        bindMessageHandler(buffer, handlers: MessageMappingProperties[], process: (data) => Observable<any>): Observable<any> {
            const data = JSON.parse(buffer.data);
            const messageHandler = handlers.find((handler) => handler.message === data.type);
            if (!messageHandler) {
                return Observable.empty();
            }
            const { callback } = messageHandler;
            return process(callback(data));
        }

    /* ... */
}

```

现在，我们已经创建了我们的第一个自定义适配器。为了使用它，我们必须在`main.ts`文件中调用`app: INestApplication`提供的`useWebSocketAdapter`，而不是 Nest.js 的`IoAdapter`，如下所示：

```js
app.useWebSocketAdapter(new WsAdapter(app));

```

我们将适配器传递给`app`实例，以便像前面的示例中所示使用它。

# 客户端

在上一节中，我们介绍了如何在服务器端设置 Web 套接字以及如何处理来自客户端的事件。

现在我们将看到如何设置客户端，以便使用 Nest.js 的`IoAdapter`或我们自定义的`WsAdapter`。为了使用`IoAdapter`，我们必须获取`socket.io-client`库并设置我们的第一个 HTML 文件。

该文件将定义一个简单的脚本，将套接字连接到具有已登录用户令牌的服务器。这个令牌将用于确定用户是否连接良好。

检查以下代码：

```js
<script>
    const socket = io('http://localhost:3000',  {
        query: 'auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
 eyJlbWFpbCI6InRlc3QzQHRlc3QuZnIiLCJpYXQiOjE1MjQ5NDk3NTgs
 ImV4cCI6MTUyNDk1MzM1OH0.QH_jhOWKockuV-w-vIKMgT_eLJb3dp6a
 ByDbMvEY5xc'
    });
</script>

```

正如您所看到的，我们在套接字连接中传递了一个名为`auth_token`的令牌到查询参数中。我们可以从套接字握手中获取它，然后验证套接字。

发出事件也很容易，参见以下示例：

```js
socket.on('connect', function () {
    socket.emit('showUser', { userId: 4 });
    socket.emit('indexComment', { entryId: 2 });
    socket.emit('showComment', { entryId: 2, commentId: 1 });
});

```

在这个例子中，我们正在等待`connect`事件，以便在连接完成时得知。然后我们发送三个事件：一个是获取用户，然后是一个条目，以及条目的评论。

通过以下`on`事件，我们能够获取服务器作为响应我们之前发出的事件而发送的数据。

```js
socket.on('indexComment', function (data) {
    console.log('indexComment', data);
});
socket.on('showComment', function (data) {
    console.log('showComment', data);
});
socket.on('showUser', function (data) {
    console.log('showUser', data);
});
socket.on('exception', function (data) {
    console.log('exception', data);
});

```

在这里，我们在控制台中显示服务器响应的所有数据，并且我们还实现了一个名为`exception`的事件，以便捕获服务器可能返回的所有异常。

当然，正如我们在身份验证章节中所见，用户无法访问另一个用户的数据。

在我们想要使用自定义适配器的情况下，流程是类似的。我们将使用以下方式打开到服务器的连接：

```js
const ws = new WebSocket("ws://localhost:3000?token=eyJhbGciO
iJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3QzQHRlc3QuZnIiL
CJpYXQiOjE1MjUwMDc2NjksImV4cCI6MTUyNTAxMTI2OX0.GQjWzdKXAFTAtO
kpLjId7tPliIpKy5Ru50evMzf15YE");

```

我们在本地主机上使用与我们的 HTTP 服务器相同的端口打开连接。我们还将令牌作为查询参数传递，以便通过`verifyClient`方法，这是我们在`WsAuthenticationGatewayMiddleware`中看到的。

接下来，我们将等待服务器的返回，以确保连接成功并可用。

```js
ws.onopen = function() {
    console.log('open');
    ws.send(JSON.stringify({ type: 'showComment', entryId: 2, commentId: 1 }));
};

```

当连接可用时，使用`send`方法发送我们想要处理的事件类型，这里是使用`showComment`，并传递适当的参数，就像我们在使用 socket.io 时所做的一样。

我们将使用`onmessage`来获取服务器为我们之前发送的事件返回的数据。当`WebSocket`接收到事件时，将发送一个`message`事件给我们可以使用以下示例捕获的管理器。

```js
ws.onmessage = function(ev) {
    const _data = JSON.parse(ev.data);
    console.log(_data);
};

```

您现在可以根据自己的喜好在客户端应用程序的其余部分中使用这些数据。

# 总结

在本章中，您学会了如何设置服务器端，以便使用：

+   由 Nest.js 的`IoAdapter`提供的`socket.io`库

+   具有自定义适配器的`ws`库

您还需要设置一个网关来处理客户端发送的事件。

您已经学会了如何设置客户端以使用`socket.io-client`或`WebSocket`客户端来连接服务器的套接字。这是在与 HTTP 服务器相同的端口上完成的，并且您学会了如何发送和捕获服务器返回的数据或在出现错误时捕获异常。

最后，您学会了如何设置身份验证中间件，以便检查提供的套接字令牌并确定用户是否经过身份验证，以便能够在`IoAdapter`或自定义适配器的情况下访问处理程序。

下一章将涵盖 Nest.js 的微服务。


# 第九章：微服务

使用 Nest.js 微服务，我们能够提取出应用程序业务逻辑的一部分，并在单独的 Nest.js 上下文中执行它。默认情况下，这个新的 Nest.js 上下文并不在新线程甚至新进程中执行。因此，“微服务”这个名称有点误导。实际上，如果您坚持使用默认的 TCP 传输，用户可能会发现请求完成的时间更长。然而，将应用程序的一些部分卸载到这个新的微服务上下文中也有好处。为了介绍基础知识，我们将坚持使用 TCP 传输，但在本章的高级架构部分中，我们将寻找一些现实世界的策略，Nest.js 微服务可以提高应用程序性能。要查看一个工作示例，请记住您可以克隆本书的附带 Git 存储库：

`git clone https://github.com/backstopmedia/nest-book-example.git`

# 服务器引导

要开始，请确保`@nestjs/microservices`已安装在您的项目中。该模块提供了客户端、服务器和所需的实用程序，以将 Nest.js API 应用程序转换为微服务应用程序。最后，我们将修改我们的博客应用程序的引导程序以启用微服务。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.connectMicroservice({
        transport: Transport.TCP,
        options: {
            port: 5667
        }
    });

    await app.startAllMicroservicesAsync();
    await app.listen(3001);
}

```

`connectMicroservice`方法指示 NestApplication 设置一个新的 NestMicroservice 上下文。该对象提供了设置 NestMicroservice 上下文的选项。在这里，我们保持简单，并使用 Nest.js 提供的标准 TCP 传输。调用`startAllMicroservicesAsync`启动 NestMicroservice 上下文。在调用 NestApplication 的`listen`之前，请务必这样做。

# 配置

传递给`connectMicroservice`的配置参数取决于我们使用的传输方式。传输是客户端和服务器的组合，它们协同工作以在 NestApplication 和 NestMicroservice 上下文之间传输微服务请求和响应。Nest.js 附带了许多内置传输，并提供了创建自定义传输的能力。可用的参数取决于我们使用的传输方式。现在，我们将使用 TCP 传输，但稍后会介绍其他传输方式。TCP 传输的可能选项包括：

+   **host**：运行 NestMicroservice 上下文的主机。默认值是假定为`localhost`，但如果 NestMicroservice 作为不同主机上的单独项目运行，例如不同的 Kubernetes pod，可以使用这个选项。

+   **port**：NestMicroservice 上下文正在侦听的端口。默认值是假定为`3000`，但我们将使用不同的端口来运行我们的 NestMicroservice 上下文。

+   **retryAttempts**：在 TCP 传输的上下文中，这是服务器在收到`CLOSE`事件后尝试重新建立自身的次数。

+   **retryDelay**：与`retryAttempts`一起工作，并延迟传输重试过程一定的毫秒数。

# 第一个微服务处理程序

对于我们的第一个微服务处理程序，让我们将 UserController 索引方法转换为微服务处理程序。为此，我们复制该方法并进行一些简单的修改。我们将不再使用`Get`来注释该方法，而是使用`MessagePattern`。

```js
@Controller()
export class UserController {

    @Get('users')
    public async index(@Res() res) {
        const users = await this.userService.findAll();
        return res.status(HttpStatus.OK).json(users);
    }

    @MessagePattern({cmd: 'users.index'})
    public async rpcIndex() {
        const users = await this.userService.findAll();
        return users;
    }
}

```

消息模式为 Nest.js 提供了确定要执行哪个微服务处理程序的手段。该模式可以是一个简单的字符串或一个复杂的对象。当发送新的微服务消息时，Nest.js 将搜索所有已注册的微服务处理程序，以找到与消息模式完全匹配的处理程序。

微服务方法本身可以执行与正常控制器处理程序几乎相同的业务逻辑来响应。与正常的控制器处理程序不同，微服务处理程序没有 HTTP 上下文。事实上，像`@Get`、`@Body`和`@Req`这样的装饰器在微服务控制器中没有意义，也不应该使用。为了完成消息的处理，处理程序可以返回一个简单的值、promise 或 RxJS Observable。

# 发送数据

之前的微服务处理程序非常牵强。更有可能的是，微服务处理程序将被实现为对数据进行一些处理并返回一些值。在正常的 HTTP 处理程序中，我们会使用`@Req`或`@Body`来从 HTTP 请求的主体中提取数据。由于微服务处理程序没有 HTTP 上下文，它们将输入数据作为方法参数。

```js
@Controller()
export class UserController {
    @Client({transport: Transport.TCP, options: { port: 5667 }})
    client: ClientProxy

    @Post('users')
    public async create(@Req() req, @Res() res) {
        this.client.send({cmd: 'users.index'}, {}).subscribe({
            next: users => {
                res.status(HttpStatus.OK).json(users);
            },
            error: error => {
                res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(error);
            }
        });
    }

    @MessagePattern({cmd: 'users.create'})
    public async rpcCreate(data: any) {
        if (!data || (data && Object.keys(data).length === 0)) throw new Error('Missing some information.');

        await this.userService.create(data);
    }
}

```

在这个例子中，我们使用`@Client`装饰器为 Nest.js 依赖注入提供了一个注入微服务客户端实例的地方。客户端装饰器接受与在引导应用程序时传递给`connectMicroservice`相同的配置对象。客户端是 NestApplication 上下文与 NestMicroservice 上下文进行通信的方式。使用客户端，我们修改了原始的`@Post('users')` API，将创建新用户的处理过程转移到了 NestMicroservice 上下文中。

![微服务 TCP 流](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/MicroserviceFlow001.png)

这张图表展示了创建新用户时数据流的简化视图。客户端与微服务上下文建立 TCP 连接，并将数据库操作的处理过程转移到微服务上下文中。`rpcCreate`方法将返回一个成功的响应和一些数据，或者一个异常。在处理微服务消息的同时，正常的控制器处理程序将等待响应。

请注意，微服务客户端的`send`方法返回一个 Observable。如果你想等待来自微服务的响应，只需订阅 Observable 并使用响应对象发送结果。另外，Nest.js 将 Observables 视为一等公民，并且它们可以从处理程序中返回。Nest.js 会负责订阅 Observable。请记住，你会失去一些对响应状态码和主体的控制。但是，你可以通过异常和异常过滤器重新获得一些控制。

# 异常过滤器

异常过滤器提供了一种将从微服务处理程序抛出的异常转换为有意义对象的方法。例如，我们的`rpcCreate`方法目前抛出一个带有字符串的错误，但是当 UserService 抛出错误或者可能是 ORM 时会发生什么。这个方法可能会抛出许多不同的错误，而调用方法唯一知道发生了什么的方法是解析错误字符串。这是完全不可接受的，所以让我们来修复它。

首先创建一个新的异常类。注意我们的微服务异常扩展了 RpcException，并且在构造函数中没有传递 HTTP 状态码。这些是微服务异常和正常的 Nest.js API 异常之间唯一的区别。

```js
export class RpcValidationException extends RpcException {
    constructor(public readonly validationErrors: ValidationError[]) {
        super('Validation failed');
    }
}

```

现在我们可以改变`rpcCreate`方法，当数据无效时抛出这个异常。

```js
@MessagePattern({cmd: 'users.create'})
public async rpcCreate(data: any) {
    if (!data || (data && Object.keys(data).length === 0)) throw new RpcValidationException();

    await this.userService.create(data);
}

```

最后，创建一个异常过滤器。微服务异常过滤器与它们的正常 API 对应物不同，它们扩展了 RpcExceptionFilter 并返回一个 ErrorObservable。这个过滤器将捕获我们创建的 RpcValidationException，并抛出一个包含特定错误代码的对象。

**注意**`throwError`方法来自 RxJS 版本 6 包。如果你仍在使用 RxJS 版本 5，使用`Observable.throw`。

```js
@Catch(RpcValidationException)
export class RpcValidationFilter implements RpcExceptionFilter {
    public catch(exception: RpcValidationException): ErrorObservable {
        return throwError({
            error_code: 'VALIDATION_FAILED',
            error_message: exception.getError(),
            errors: exception.validationErrors
        });
    }
}

```

当新的异常发生时，我们所要做的就是采取行动。修改`create`方法以捕获从微服务客户端抛出的任何异常。在捕获中，检查`error_code`字段是否具有`VALIDATION_FAILED`的值。当它是这样时，我们可以向用户返回`400`的 HTTP 状态码。这将允许用户的客户端，即浏览器，以不同的方式处理错误，可能向用户显示一些消息并允许他们修复输入的数据。与将所有错误作为`500`的 HTTP 状态码返回给客户端相比，这提供了更好的用户体验。

```js
@Post('users')
public async create(@Req() req, @Res() res) {
    this.client.send({cmd: 'users.create'}, body).subscribe({
        next: () => {
            res.status(HttpStatus.CREATED).send();
        },
        error: error => {
            if (error.error_code === 'VALIDATION_FAILED') {
                res.status(HttpStatus.BAD_REQUEST).send(error);
            } else {
                res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(error);
            }
        }
    });
}

```

# 管道

Nest.js 中最常用的管道是 ValidationPipe。然而，这个管道不能与微服务处理程序一起使用，因为它会抛出扩展 HttpException 的异常。在微服务中抛出的所有异常都必须扩展 RpcException。为了解决这个问题，我们可以扩展 ValidationPipe，捕获 HttpException，并抛出 RpcException。

```js
@Injectable()
export class RpcValidationPipe extends ValidationPipe implements PipeTransform<any> {
    public async transform(value: any, metadata: ArgumentMetadata) {
        try {
            await super.transform(value, metadata);
        } catch (error) {
            if (error instanceof BadRequestException) {
                throw new RpcValidationException();
            }

            throw error;
        }

        return value;
    }
}

```

在使用 ValidationPipe 之前，我们必须创建一个描述我们微服务方法期望的数据格式的类。

```js
class CreateUserRequest {
      @IsEmail()
      @IsNotEmpty()
      @IsDefined()
      @IsString()
      public email: string;

      @Length(8)
      @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)\S+$/)
      @IsDefined()
      @IsString()
      public password: string;

      @IsNotEmpty()
      @IsDefined()
      @IsString()
      public firstName: string;

      @IsNotEmpty()
      @IsDefined()
      @IsString()
      public lastName: string;
}

```

新的请求类使用`class-validator` NPM 包来验证从 Nest.js 微服务模块传递给我们微服务方法的对象。该类包含所有属性，并使用特定的装饰器描述这些属性应包含的内容。例如，`email`属性应该是一个电子邮件地址，不能是空的，必须被定义，并且必须是一个字符串。现在我们只需要将其连接到我们的`rpcCreate`方法。

```js
@MessagePattern({cmd: 'users.create'})
@UsePipes(new RpcValidationPipe())
@UseFilters(new RpcValidationFilter())
public async rpcCreate(data: CreateUserRequest) {
    await this.userService.create(data);
}

```

由于微服务处理程序不使用`@Body`装饰器，我们需要使用`@UsePipes`来使用我们的新的 RpcValidationPipe。这将指示 Nest.js 根据其类类型验证输入数据。就像对 API 一样，使用验证类和 RpcValidationPipe 来将输入验证从控制器或微服务方法中卸载出来。

# 守卫

在微服务中，守卫的作用与普通 API 中的作用相同。它们确定特定的微服务处理程序是否应该处理请求。到目前为止，我们已经使用守卫来保护 API 处理程序免受未经授权的访问。我们应该对我们的微服务处理程序做同样的事情。尽管在我们的应用程序中，我们的微服务处理程序只从我们已经受保护的 API 处理程序中调用，但我们永远不应该假设这将始终是这种情况。

```js
@Injectable()
export class RpcCheckLoggedInUserGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const data = context.switchToRpc().getData();
        return Number(data.userId) === data.user.id;
    }
}

```

新的守卫看起来与 API 的`CheckLoggedInUserGuard`守卫完全相同。不同之处在于传递给`canActivate`方法的参数。由于这个守卫是在微服务的上下文中执行的，它将获得一个微服务`data`对象，而不是 API 请求对象。

我们使用新的微服务守卫与我们之前使用 API 守卫的方式相同。只需在微服务处理程序上添加`@UseGuards`装饰器，我们的守卫现在将保护我们的微服务免受滥用。让我们为检索当前用户信息创建一个新的微服务。

```js
@Get('users/:userId')
@UseGuards(CheckLoggedInUserGuard)
public async show(@Param('userId') userId: number, @Req() req, @Res() res) {
    this.client.send({cmd: 'users.show'}, {userId, user: req.user}).subscribe({
        next: user => {
            res.status(HttpStatus.OK).json(user);
        },
        error: error => {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).send(error);
        }
    });
}

@MessagePattern({cmd: 'users.show'})
@UseGuards(RpcCheckLoggedInUserGuard)
public async rpcShow(data: any) {
    return await this.userService.findById(data.userId);
}

```

`show` API 处理程序现在将访问数据库的繁重工作交给了 NestMicroservice 上下文。微服务处理程序上的守卫确保，如果处理程序以某种方式在`show`API 处理程序之外被调用，它仍将保护用户数据免受未经授权的请求。但仍然存在一个问题。这个示例从数据库返回整个用户对象，包括散列密码。这是一个安全漏洞，最好通过拦截器来解决。

# 拦截器

微服务拦截器的功能与普通 API 拦截器没有任何不同。唯一的区别是拦截器接收到的是发送到微服务处理程序的数据对象，而不是 API 请求对象。这意味着您实际上可以编写一次拦截器，并在两种情境下使用它们。与 API 拦截器一样，微服务拦截器在微服务处理程序之前执行，并且必须返回一个 Observable。为了保护我们的`rpcShow`微服务端点，我们将创建一个新的拦截器，该拦截器将期望一个`User`数据库对象并移除`password`字段。

```js
@Injectable()
export class CleanUserInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, stream$: Observable<any>): Observable<any> {
        return stream$.pipe(
            map(user => JSON.parse(JSON.stringify(user))),
            map(user => {
                return {
                    ...user,
                    password: undefined
                };
            })
        );
    }
}

```

```js
@MessagePattern({cmd: 'users.show'})
@UseGuards(RpcCheckLoggedInUserGuard)
@UseInterceptors(CleanUserInterceptor)
public async rpcShow(data: any) {
    return await this.userService.findById(data.userId);
}

```

`rpcShow`微服务处理程序的响应现在将删除`password`字段。请注意，在拦截器中，我们必须将`User`数据库对象转换为 JSON 格式。这可能会因您使用的 ORM 而有所不同。使用 Sequelize，我们需要从数据库响应中获取原始数据。这是因为 ORM 的响应实际上是一个包含许多不同 ORM 方法和属性的类。通过将其转换为 JSON 格式，然后使用`password: undefined`的扩展运算符来删除`password`字段。

# 内置传输

TCP 传输只是 Nest.js 内置的几种传输方式之一。使用 TCP 传输，我们必须将 NestMicroservice 上下文绑定到另一个端口，占用服务器上的另一个端口，并确保 NestMicroservice 上下文在启动 NestApplication 上下文之前运行。其他内置传输可以克服这些限制并增加额外的好处。

## Redis

[Redis](https://redis.io/)是一个简单的内存数据存储，可以用作发布-订阅消息代理。Redis 传输利用了[redis](https://github.com/NodeRedis/node_redis) NPM 包和 Redis 服务器之间传递消息的 NestApplication 和 NestMicroservice 上下文。要使用 Redis 传输，我们需要更新我们的`bootstrap`方法以使用正确的 NestMicroservice 配置。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.connectMicroservice({
        transport: Transport.REDIS,
        options: {
            url: process.env.REDIS_URL
        }
    });

    await app.startAllMicroservicesAsync();
    await app.listen(3001);
}

```

您还必须更新所有使用`@Client`装饰器的位置，以使用相同的设置。相反，让我们将此配置集中化，这样我们就不会重复代码，并且可以更轻松地切换传输方式。

```js
export const microserviceConfig: RedisOptions = {
    transport: Transport.REDIS,
    options: {
        url: process.env.REDIS_URL
    }
};

```

Redis 传输可以采用以下选项：

+   **url**：Redis 服务器的 URL。默认值为`redis://localhost:6379`。

+   **retryAttempts**：当连接丢失时，微服务服务器和客户端将尝试重新连接到 Redis 服务器的次数。这用于为`redis` NPM 包创建`retry_strategy`。

+   **retryDelay**：与`retryAttempts`配合使用，以毫秒为单位延迟传输的重试过程。

现在我们可以更新应用程序的`bootstrap`以使用我们创建的`microserviceConfig`对象。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.connectMicroservice(microserviceConfig);

    await app.startAllMicroservicesAsync();
    await app.listen(3001);
}

```

最后，在 UserController 中更新`@Client`装饰器。

```js
@Controller()
export class UserController {
    @Client(microserviceConfig)
    client: ClientProxy
}

```

启动 Redis 服务器，例如[redis docker image](https://hub.docker.com/_/redis/)和应用程序，所有我们的微服务事务现在将通过 Redis 服务器进行处理。下面的图表显示了在创建新用户并使用 Redis 传输时的数据流的简化视图。

![微服务 Redis 流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/MicroserviceFlow002.png)

客户端和服务器都与 Redis 服务器建立连接。当调用`client.send`时，客户端会即时修改消息模式以创建发布和订阅通道。服务器消费消息并移除消息模式修改以找到正确的微服务处理程序。一旦微服务处理程序完成处理，模式再次被修改以匹配订阅通道。客户端消费这条新消息，取消订阅订阅通道，并将响应传递回调用者。

## MQTT

[MQTT](http://mqtt.org/)是一种简单的消息协议，旨在在网络带宽有限时使用。MQTT 传输利用[mqtt](https://github.com/mqttjs/MQTT.js) NPM 软件包和远程 MQTT 服务器在 NestApplication 和 NestMicroservice 上下文之间传递消息。数据流和微服务客户端和服务器的操作方式几乎与 Redis 传输相同。要使用 MQTT 传输，让我们更新 microserviceConfig 配置对象。

```js
export const microserviceConfig: MqttOptions = {
    transport: Transport.MQTT,
    options: {
        url: process.env.MQTT_URL
    }
};

```

MQTT 传输可以采用几种选项，所有这些选项都在`mqtt` NPM 软件包的 Github 存储库中详细说明。最值得注意的是，传输将`url`选项默认设置为`mqtt://localhost:1883`，并且没有连接重试。如果与 MQTT 服务器的连接丢失，微服务消息将不再传递。

启动 MQTT 服务器，例如[eclipse-mosquitto docker image](https://hub.docker.com/_/eclipse-mosquitto/)，现在应用程序和所有微服务事务将通过 MQTT 服务器进行处理。

## NATS

[NATS](https://nats.io/)是一个自称具有极高吞吐量的开源消息代理服务器。NATS 传输利用[nats](https://github.com/nats-io/node-nats) NPM 软件包和远程 NATS 服务器在 NestApplication 和 NestMicroservice 上下文之间传递消息。

```js
export const microserviceConfig: MqttOptions = {
    transport: Transport.NATS,
    options: {
        url: process.env.NATS_URL
    }
};

```

NATS 传输可以采用以下选项：

+   **url**：NATS 服务器的 URL。默认值为`nats://localhost:4222`。

+   **name**/**pass**：用于将 Nest.js 应用程序与 NATS 服务器进行身份验证的用户名和密码。

+   **maxReconnectAttempts**：当连接丢失时，服务器和客户端尝试重新连接到 NATS 服务器的次数。默认值是尝试重新连接 10 次。

+   **reconnectTimeWait**：与`maxReconnectAttempts`配合使用，以毫秒为单位延迟传输的重试过程。

+   **servers**：一组`url`字符串，所有这些字符串都是 NATS 服务器。这允许传输利用 NATS 服务器集群。

+   **tls**：一个布尔值，指示连接到 NATS 服务器时是否应使用 TLS。**注意**，默认值为 false，这意味着所有消息都以明文传递。也可以提供对象而不是布尔值，并且可以包含标准的 Node TLS 设置，如客户端证书。

启动 NATS 服务器，例如[nats docker image](https://hub.docker.com/_/nats/)，现在应用程序和所有微服务事务将通过 NATS 服务器进行处理。下面的图表显示了在创建新用户并使用 NATS 传输时数据流的简化视图。

![微服务 NATS 流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/MicroserviceFlow003.png)

客户端和服务器都与 NATS 服务器建立连接。当调用`client.send`时，客户端会即时修改消息模式以创建发布和订阅队列。Redis 传输和 NATS 传输之间最显着的区别之一是 NATS 传输使用队列组。这意味着现在我们可以有多个 NestMicroservice 上下文，并且 NATS 服务器将在它们之间负载平衡消息。服务器消耗消息并移除消息模式修改以找到正确的微服务处理程序。一旦微服务处理程序完成处理，模式将再次修改以匹配订阅通道。客户端消耗这条新消息，取消订阅订阅通道，并将响应传递给调用者。

## gRPC

[gRPC](https://grpc.io)是一个远程过程调用客户端和服务器，旨在与 Google 的[Protocol Buffers](https://developers.google.com/protocol-buffers/)一起使用。gRPC 和协议缓冲区是值得拥有自己的书籍的广泛主题。因此，我们将继续讨论在 Nest.js 应用程序中设置和使用 gRPC。要开始，我们需要[grpc](https://github.com/grpc/grpc-node) NPM 包。在我们可以为 Nest.js 应用程序编写任何代码之前，我们必须编写一个协议缓冲区文件。

```js
syntax = "proto3";

package example.nestBook;

message User {
    string firstName = 1;
    string lastName = 2;
    string email = 3;
}

message ShowUserRequest {
    double userId = 1;
}

message ShowUserResponse {
    User user = 1;
}

service UserService {
    rpc show (ShowUserRequest) returns (ShowUserResponse);
}

```

上面的代码片段描述了一个名为`UserService`的单个 gRPC 服务。这通常将映射到您自己项目中的一个服务或控制器。该服务包含一个名为`show`的方法，该方法接受一个带有`userId`的对象，并返回一个带有`user`属性的对象。`syntax`值指示 gRPC 包我们使用的协议缓冲区语言的格式。`package`声明充当我们在 proto 文件中定义的所有内容的命名空间。在导入和扩展其他 proto 文件时，这是最有用的。

**注意：**我们保持了 proto 文件的简单，以便我们可以专注于配置 Nest.js 以使用 gRPC 微服务。

与所有其他传输方式一样，我们现在需要在我们的控制器中配置 NestMicroservice 上下文和微服务客户端。

```js
export const microserviceConfig: GrpcOptions = {
    transport: Transport.GRPC,
    options: {
        url: '0.0.0.0:5667',
        protoPath: join(__dirname, './nest-book-example.proto'),
        package: 'example.nestBook'
    }
};

```

gRPC 传输可以采用以下选项：

+   **url**：gRPC 服务器的 URL。默认值为`localhost:5000`。

+   凭证：来自`grpc` NPM 包的`ServerCedentials`对象。默认情况下，使用`grpc.getInsecure`方法来检索默认凭证对象。这将禁用 TLS 加密。为了建立安全的通信通道，请使用`grpc.createSsl`并提供根 CA、私钥和公钥证书。有关凭证的更多信息可以在[这里](https://grpc.io/grpc/node/grpc.credentials.html)找到。

+   **protoPath**：proto 文件的绝对路径。

+   **root**：所有 proto 文件所在位置的绝对路径。这是一个可选选项，如果您不在自己的项目中导入其他 proto 文件，则很可能不需要。如果定义了此选项，它将被预置到`protoPath`选项之前。

+   **package**：用于客户端和服务器的包的名称。这应该与 proto 文件中给出的包名称匹配。

在我们真正使用 gRPC 传输之前，我们需要对我们的控制器进行一些更改。

```js
@Controller()
export class UserController implements OnModuleInit {
    @Client(microserviceConfig)
    private client: ClientGrpc;
    private protoUserService: IProtoUserService;

    constructor(
        private readonly userService: UserService
    ) {
    }

    public onModuleInit() {
        this.protoUserService = this.client.getService<IProtoUserService>('UserService');
    }
}

```

请注意，我们仍然使用`@Client`装饰的`client`属性，但我们有一个新类型`ClientGrpc`和一个新属性`protoUserService`。使用 gRPC 传输时注入的客户端不再包含`send`方法。相反，它具有一个`getService`方法，我们必须使用它来检索我们在 proto 文件中定义的服务。我们使用`onModuleInit`生命周期钩子，以便在 Nest.js 实例化我们的模块之后立即检索 gRPC 服务，而在任何客户端尝试使用控制器 API 之前。`getService`方法是一个通用方法，实际上并不包含任何方法定义。相反，我们需要提供我们自己的方法。

```js
import { Observable } from 'rxjs';

export interface IProtoUserService {
    show(data: any): Observable<any>;
}

```

我们可以对我们的接口更加明确，但这可以传达要点。现在我们控制器中的`protoUserService`属性将具有一个`show`方法，允许我们调用`show` gRPC 服务方法。

```js
@Get('users/:userId')
@UseGuards(CheckLoggedInUserGuard)
public async show(@Param('userId') userId: number, @Req() req, @Res() res) {
    this.protoUserService.show({ userId: parseInt(userId.toString(), 10) }).subscribe({
        next: user => {
            res.status(HttpStatus.OK).json(user);
        },
        error: error => {
            res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(error);
        }
    });
}

@GrpcMethod('UserService', 'show')
public async rpcShow(data: any) {
    const user =  await this.userService.findById(data.userId);
    return {
        user: {
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email
        }
    };
}

```

控制器的`show` API 方法已更新为使用`protoUserService.show`。这将调用`rpcShow`方法，但通过 gRPC 微服务传输。`rpcShow`方法包含不同的装饰器`@GrpcMethod`，而不是`@MessagePattern`。这对于所有 gRPC 微服务处理程序是必需的，因为微服务不再匹配模式，而是调用定义的 gRPC 服务方法。实际上，这是`@GrpcMethod`装饰器的两个可选参数的映射：服务名称和服务方法。

```js
export class UserController implements OnModuleInit {
    @GrpcMethod()
    public async rpcShow(data: any) {
    }
}

```

在上面的例子中，我们在调用`@GrpcMethod`装饰器时没有定义服务名称和服务方法。Nest.js 将自动将这些值映射到方法和类名。在这个例子中，这相当于`@GrpcMethod('UserController', 'rpcShow')`。

您可能已经注意到我们将`0.0.0.0:5667`作为我们 gRPC 服务器的 URL。当我们启动 Nest.js 应用程序时，它将在本地主机上创建一个 gRPC 服务器，并在端口`5667`上进行监听。从表面上看，这可能看起来像 TCP 传输的更复杂版本。但是，gRPC 传输的强大之处直接源自协议缓冲区的语言和平台不可知性。这意味着我们可以创建一个使用 gRPC 公开微服务的 Nest.js 应用程序，该微服务可以被任何其他语言或平台使用，只要它也使用协议缓冲区连接到我们的微服务。我们还可以创建 Nest.js 应用程序，连接到可能在其他语言（如 Go）中公开的微服务。

![微服务 gRPC 流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/nest-prgs-node-fw/img/MicroserviceFlow004.png)

当使用 gRPC 传输连接到两个或更多不同 URL 的服务时，我们需要创建相等数量的 gRPC 客户端连接，每个服务器一个。上面的图表显示了如果我们将示例博客应用程序中的评论的 crud 操作转移到 Go 服务器中，处理将会是什么样子。我们使用 gRPC 客户端连接到 Nest.js 应用程序中托管的用户微服务，另外一个连接到 Go 应用程序中托管的评论微服务。

使用任何其他传输都可以获得相同的设置。但是，您需要编写额外的代码来序列化和反序列化 Nest.js 应用程序和托管微服务的 Go 应用程序之间的消息。通过使用 gRPC 传输，协议缓冲区会为您处理这些问题。

# 自定义传输

自定义传输允许您为 NestApplication 和 NestMicroservice 上下文之间的通信定义新的微服务客户端和服务器。您可能出于多种原因想要创建自定义传输策略：您或您的公司已经有一个没有内置 Nest.js 传输的消息代理服务，或者您需要自定义内置传输的工作方式。在我们的例子中，我们将通过实现一个新的 RabbitMQ 传输来工作。

```js
export class RabbitMQTransportServer extends Server implements CustomTransportStrategy {
    private server: amqp.Connection = null;
    private channel: amqp.Channel = null;

    constructor(
        private readonly url: string,
        private readonly queue: string
    ) {
        super();
    }
}

```

Nest.js 要求所有自定义传输都实现`CustomTransportStrategy`接口。这迫使我们定义自己的`listen`和`close`方法。在我们的例子中，我们连接到 RabbitMQ 服务器并监听特定的频道。关闭服务器就像从 RabbitMQ 服务器断开连接一样简单。

```js
public async listen(callback: () => void) {
    await this.init();
    callback();
}

public close() {
    this.channel && this.channel.close();
    this.server && this.server.close();
}

private async init() {
    this.server = await amqp.connect(this.url);
    this.channel = await this.server.createChannel();
    this.channel.assertQueue(`${this.queue}_sub`, { durable: false });
    this.channel.assertQueue(`${this.queue}_pub`, { durable: false });
}

```

通过扩展 Nest.js 的`Server`类，我们的自定义传输预先配备了 RxJS 处理消息的功能，这使得 Nest.js 非常出色。然而，我们的自定义传输目前并没有真正处理消息。我们需要添加逻辑，以确定消息将如何通过 RabbitMQ 发送和接收到我们的自定义传输。

```js
public async listen(callback: () => void) {
    await this.init();
    this.channel.consume(`${this.queue}_sub`, this.handleMessage.bind(this), {
        noAck: true,
    });
    callback();
}

private async handleMessage(message: amqp.Message) {
    const { content } = message;
    const packet = JSON.parse(content.toString()) as ReadPacket & PacketId;
    const handler = this.messageHandlers[JSON.stringify(packet.pattern)];

    if (!handler) {
        return this.sendMessage({
            id: packet.id,
            err: NO_PATTERN_MESSAGE
        });
    }

    const response$ = this.transformToObservable(await handler(packet.data)) as Observable<any>;
    response$ && this.send(response$, data => this.sendMessage({
        id: packet.id,
        ...data
    }));
}

private sendMessage(packet: WritePacket & PacketId) {
    const buffer = Buffer.from(JSON.stringify(packet));
    this.channel.sendToQueue(`${this.queue}_pub`, buffer);
}

```

自定义传输现在将在`sub`频道上监听传入的消息，并在`pub`频道上发送响应。`handleMessage`方法解码消息的内容字节数组，并使用嵌入的模式对象找到正确的微服务处理程序来处理消息。例如，`{cmd: 'users.create'}`将由`rpcCreate`处理程序处理。最后，我们调用处理程序，将响应转换为 Observable，并将其传递回 Nest.js 的`Server`类。一旦提供了响应，它将通过我们的`sendMessage`方法传递，并通过`pub`频道传出。

由于服务器没有客户端是无用的，我们也需要创建一个客户端。RabbitMQ 客户端必须扩展 Nest.js 的`ClientProxy`类，并为`close`、`connect`和`publish`方法提供重写。

```js
export class RabbitMQTransportClient extends ClientProxy {
    private server: amqp.Connection;
    private channel: amqp.Channel;
    private responsesSubject: Subject<amqp.Message>;

    constructor(
        private readonly url: string,
        private readonly queue: string) {
        super();
    }

    public async close() {
        this.channel && await this.channel.close();
        this.server && await this.server.close();
    }

    public connect(): Promise<void> {
        return new Promise(async (resolve, reject) => {
            try {
                this.server = await amqp.connect(this.url);
                this.channel = await this.server.createChannel();

                const { sub, pub } = this.getQueues();
                await this.channel.assertQueue(sub, { durable: false });
                await this.channel.assertQueue(pub, { durable: false });

                this.responsesSubject = new Subject();
                this.channel.consume(pub, (message) => { this.responsesSubject.next(message); }, { noAck: true });
                resolve();
            } catch (error) {
                reject(error);
            }
        });
    }

    protected async publish(partialPacket: ReadPacket, callback: (packet: WritePacket) => void) {
    }

    private getQueues() {
        return { pub: `${this.queue}_pub`, sub: `${this.queue}_sub` };
    }
}

```

在我们的示例中，我们创建了一个新的连接到 RabbitMQ 服务器，并指定了`pub`和`sub`通道。客户端与服务器相比，使用了相反的通道配置。客户端通过`sub`通道发送消息，并在`pub`通道上监听响应。我们还利用了 RxJS 的强大功能，通过将所有响应导入 Subject 来简化`publish`方法中的处理。让我们实现`publish`方法。

```js
protected async publish(partialPacket: ReadPacket, callback: (packet: WritePacket) => void) {
    if (!this.server || !this.channel) {
        await this.connect();
    }

    const packet = this.assignPacketId(partialPacket);
    const { sub } = this.getQueues();

    this.responsesSubject.asObservable().pipe(
        pluck('content'),
        map(content => JSON.parse(content.toString()) as WritePacket & PacketId),
        filter(message => message.id === packet.id),
        take(1)
    ).subscribe(({err, response, isDisposed}) => {
        if (isDisposed || err) {
            callback({
                err,
                response: null,
                isDisposed: true
            });
        }

        callback({err, response});
    });

    this.channel.sendToQueue(sub, Buffer.from(JSON.stringify(packet)));
}

```

`publish`方法首先为消息分配一个唯一的 ID，并订阅响应主题以将响应发送回微服务调用者。最后，调用`sendToQueue`将消息作为字节数组发送到`sub`通道。一旦收到响应，就会触发对响应主题的订阅。订阅流的第一件事是提取响应的`content`并验证消息 ID 是否与最初调用`publish`时分配的 ID 匹配。这可以防止客户端处理不属于特定`publish`执行上下文的消息响应。简而言之，客户端将接收每个微服务响应，甚至可能是针对不同微服务或相同微服务的不同执行的响应。如果 ID 匹配，客户端会检查错误并使用`callback`将响应发送回微服务调用者。

在我们可以使用新传输之前，我们需要更新之前创建的微服务配置对象。

```js
export const microserviceConfig = {
    url: process.env.AMQP_URL
};

export const microserviceServerConfig: (channel: string) => CustomStrategy = channel => {
    return {
        strategy: new RabbitMQTransportServer(microserviceConfig.url, channel)
    }
};

```

现在我们有了一个方法，可以实例化我们的自定义传输服务器。这在我们应用程序的`bootstrap`中用于将我们的 NestMicroservice 上下文连接到 RabbitMQ 服务器。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.connectMicroservice(microserviceServerConfig('nestjs_book'));

    await app.startAllMicroservicesAsync();
    await app.listen(3001);
}

```

我们自定义传输的最后一部分在我们的控制器中。由于我们使用自定义传输，我们不能再使用`@ClientProxy`装饰器。相反，我们必须自己实例化我们的自定义传输。你可以在构造函数中这样做：

```js
@Controller()
export class UserController {
    client: ClientProxy;

    constructor(private readonly userService: UserService) {
        this.client = new RabbitMQTransportClient(microserviceConfig.url, 'nestjs_book');
    }
}

```

等等！你现在在控制器和自定义传输客户端之间创建了一个硬绑定。这会使将来迁移到不同策略变得更加困难，而且非常难以测试。相反，让我们利用 Nest.js 的依赖注入来创建我们的客户端。首先创建一个新模块来容纳和公开我们的自定义传输客户端。

```js
const ClientProxy = {
  provide: 'ClientProxy',
  useFactory: () => new RabbitMQTransportClient(microserviceConfig.url, 'nestjs_book')
};

@Module({
    imports: [],
    controllers: [],
    components: [ClientProxy],
    exports: [ClientProxy]
})
export class RabbitMQTransportModule {}

```

在我们的示例中，我们给我们的组件注入了标记为`'ClientProxy'`的注入令牌。这只是为了保持简单，你可以随意更改它。重要的是确保用于注册组件的注入令牌也是我们在控制器构造函数中放置`@Inject`装饰器时使用的注入令牌。

```js
@Controller()
export class UserController {

    constructor(
        private readonly userService: UserService,
        @Inject('ClientProxy')
        private readonly client: ClientProxy
    ) {
    }

```

我们的控制器现在将在运行时注入一个微服务客户端，允许 API 处理程序与微服务处理程序进行通信。更好的是，客户端现在可以在测试中被模拟重写。启动一个 RabbitMQ 服务器，比如[rabbitmq docker image](https://hub.docker.com/_/rabbitmq/)，并设置`AMQP_URL`环境变量，即`amqp://guest:guest@localhost:5672`，所有微服务请求将通过 RabbitMQ 服务器进行处理。

在我们的 RabbitMQ 示例中，微服务客户端和服务器的数据流以及操作方式几乎与 NATS 传输相同。就像 NATS 一样，RabbitMQ 提供了多个 NestMicroservice 上下文消费消息的能力。RabbitMQ 将在所有消费者之间进行负载均衡。

# 混合应用程序

当我们在本章开始实现微服务时，我们修改了启动方法来调用`connectMicroservice`。这是一个特殊的方法，将我们的 Nest.js 应用程序转换为混合应用程序。这意味着我们的应用程序现在包含多种上下文类型。这很简单，但这有一些影响，你应该意识到。具体来说，使用混合应用程序方法，你将无法再为 NestMicroservice 上下文附加全局过滤器、管道、守卫和拦截器。这是因为 NestMicroservice 上下文会立即启动，但在混合应用程序中不会连接。为了解决这个限制，我们可以独立地创建我们的两个上下文。

```js
async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const rpcApp = await NestFactory.createMicroservice(AppModule, microserviceServerConfig('nestjs_book'));
    rpcApp.useGlobalFilters(new RpcValidationFilter());

    await rpcApp.listenAsync();
    await app.listen(process.env.PORT || 3000);
}

```

现在我们正在独立创建两个应用程序上下文，我们可以利用 NestMicroservice 上下文的全局变量。为了测试这一点，我们可以更新`rpcCreate`处理程序以删除`RpcValidationFilter`。在这一点上执行应用程序仍然应该导致在请求`create`API 时不包含必需字段时返回验证错误。

```js
@MessagePattern({cmd: 'users.create'})
public async rpcCreate(data: CreateUserRequest) {
    if (!data || (data && Object.keys(data).length === 0)) throw new RpcValidationException();
    await this.userService.create(data);
}

```

我们可以扩展这种启动应用程序的方法，将更多的应用程序拆分为独立的上下文。这仍然不使用多个进程或线程，但通过使用一些更高级的架构设计，我们可以获得这些好处。

# 高级架构设计

到目前为止，我们已经涵盖了在 Nest.js 中设置和开始编写和使用微服务所需的一切。在这一过程中，我们描述了 Nest.js 微服务的一些缺点。特别是，由于微服务不在单独的线程或进程中运行，使用 Nest.js 微服务时可能在性能方面并没有太多收益。

然而，并不是说你不能获得这些好处。Nest.js 只是没有提供开箱即用的工具。在大多数关于在生产环境中运行 NodeJS 应用程序的资料中，通常总是涵盖并推荐使用 NodeJS 的`cluster`模块。我们可以在我们的 Nest.js 应用程序中做同样的事情。

```js
async function bootstrapApp() {
    const app = await NestFactory.create(AppModule);

    await app.listen(process.env.PORT || 3000);
}

async function bootstrapRpc() {
    const rpcApp = await NestFactory.createMicroservice(AppModule, microserviceServerConfig('nestjs_book'));
    rpcApp.useGlobalFilters(new RpcValidationFilter());

    await rpcApp.listenAsync();
}

if (cluster.isMaster) {
    const appWorkers = [];
    const rpcWorkers = [];

    for (let i = 0; i < os.cpus().length; i++) {
        const app = cluster.fork({
            APP_TYPE: 'NestApplication'
        });
        const rpc = cluster.fork({
            APP_TYPE: 'NestMicroservice'
        });

        appWorkers.push(app);
        rpcWorkers.push(rpc);
    }

    cluster.on('exit', function(worker, code, signal) {
        if (appWorkers.indexOf(worker) > -1) {
            const index = appWorkers.indexOf(worker);
            const app = cluster.fork({
                APP_TYPE: 'NestApplication'
            });
            appWorkers.splice(index, 1, app);
        } else if (rpcWorkers.indexOf(worker) > -1) {
            const index = rpcWorkers.indexOf(worker);
            const rpc = cluster.fork({
                APP_TYPE: 'NestMicroservice'
            });
            rpcWorkers.splice(index, 1, rpc);
        }
    });
} else {
    if (process.env.APP_TYPE === 'NestApplication') {
        bootstrapApp();
    } else if (process.env.APP_TYPE === 'NestMicroservice') {
        bootstrapRpc();
    }
}

```

现在，我们的 NestApplication 和 NestMicroservice 上下文不仅在自己的线程上运行，而且根据服务器上可用的 CPU 数量进行集群化。对于每个 CPU，将创建一个单独的 NestApplication 和 NestMicroservice 上下文。NestApplication 上下文线程将共享主应用程序端口。最后，由于我们使用 RabbitMQ，运行多个 NestMicroservice 上下文，我们有多个订阅者等待微服务消息。RabbitMQ 将负责在所有 NestMicroservice 实例之间负载平衡消息分发。我们使我们的应用程序更具弹性，更能够处理比本章开始时更多的用户负载。

# 摘要

在本章开始时，我们说“微服务”是 Nest.js 的一个误导性名称。事实上，情况可能仍然如此，但这实际上取决于许多因素。我们最初使用 TCP 传输的示例几乎无法符合所有传统定义的微服务。NestApplication 和 NestMicroservice 上下文都是从同一个进程中执行的，这意味着一个的灾难性故障可能会导致两者都崩溃。

在突出 Nest.js 开箱即用的所有传输方式之后，我们在示例博客应用程序中使用自定义的 RabbitMQ 传输重新实现了我们的微服务。我们甚至将 NestApplication 和 NestMicroservice 上下文运行在自己的线程中。这是朝着实现“微服务”名称的正确方向迈出的重要一步。

尽管我们在本书中没有涵盖具体细节，但现在显而易见的是，您不仅限于在同一个 Nest.js 项目或存储库中使用微服务。使用诸如 Redis 和 RabbitMQ 之类的传输方式，我们可以创建并使用多个 Nest.js 项目，其唯一目的是执行 NestMicroservice 上下文。所有这些项目都可以独立在 Kubernetes 集群中运行，并通过 Redis 或 RabbitMQ 传递消息进行访问。更好的是，我们可以使用内置的 gRPC 传输与其他语言编写的微服务进行通信，并部署到其他平台上。

在下一章中，我们将学习 Nest.js 中的路由和请求处理。
