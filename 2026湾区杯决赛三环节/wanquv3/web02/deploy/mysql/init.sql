-- init.sql — 环节三 web02（idap.article / idap.flag）还原
-- 说明：线上实测数据库名为 `idap`，表 `article(id,title,content)` 与 `flag(flag)`；
--       article 初始 10 行（实测 `'-- -` 命中 10 条）；第 3 列 `content` 会回显（UNION 利用点）。
--       flag 真值由 docker-compose 的 FLAG 环境变量给出，app.py 启动时同步进 idap.flag。

CREATE DATABASE IF NOT EXISTS `idap` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `idap`;

DROP TABLE IF EXISTS `article`;
CREATE TABLE `article` (
  `id`      INT(11)      NOT NULL AUTO_INCREMENT,
  `title`   VARCHAR(255) NOT NULL,
  `content` TEXT         NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `article` (`id`, `title`, `content`) VALUES
(1,  '智能数据分析平台正式发布',
     '智能数据分析平台依托先进的算法模型，能够快速处理海量数据，将复杂的原始数据转化为可落地的商业洞察，帮助企业提升35%的决策效率。'),
(2,  '大数据智能分析与研判引擎技术白皮书',
     '研判引擎采用多模态融合架构，覆盖结构化与非结构化数据，支持实时流式计算与离线批处理双通道，单集群日处理能力超过百亿条记录。'),
(3,  '全维度安全防护体系上线公告',
     '平台已完成全维度安全防护体系建设，涵盖边界防护、主机加固、数据加密与审计溯源四大层面，并引入AI WAF对应用层攻击进行语义级识别。'),
(4,  'AI WAF 拦截能力说明',
     'AI WAF 基于语义理解与行为建模，对SQL注入、命令注入、XSS等常见攻击具备精准识别能力，误报率低于千分之一，常规攻击payload会被直接拦截。'),
(5,  '数据资产分类分级管理办法',
     '依据数据敏感程度将数据资产划分为公开、内部、秘密、机密四个等级，不同等级对应差异化的访问控制策略与流转审批流程。'),
(6,  '智能研判在金融风控中的实践',
     '通过关联图谱与时序异常检测，平台可在毫秒级识别可疑交易链路，已在多家金融机构完成试点，风险识别准确率提升至99.2%。'),
(7,  '平台高可用架构介绍',
     '采用多活数据中心部署，计算与存储分离，任一可用区故障时可在30秒内完成流量切换，保障业务连续性达到99.99%。'),
(8,  '数据治理最佳实践指南',
     '数据治理需从标准、质量、安全、生命周期四个维度协同推进，建立数据资产目录与血缘关系图谱是治理工作的首要前提。'),
(9,  '行业解决方案：智能制造',
     '面向智能制造场景，平台提供设备物联接入、工艺参数优化与预测性维护能力，帮助产线降低非计划停机时间。'),
(10, '客户案例：某大型企业数字化转型',
     '该企业通过引入智能数据分析平台，打通了12个业务系统的数据孤岛，管理层决策周期由周级缩短至小时级，运营成本显著下降。');

DROP TABLE IF EXISTS `flag`;
CREATE TABLE `flag` (
  `id`   INT(11)      NOT NULL AUTO_INCREMENT,
  `flag` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 占位值；容器启动时 app.py 会用环境变量 FLAG 覆盖
INSERT INTO `flag` (`id`, `flag`) VALUES (1, 'flag{PLACEHOLDER_web02r3_replace_me}');
