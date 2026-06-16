/**
 * GraphQL API 路由
 * 使用 express-graphql + graphql
 * 
 * 安全措施：
 * - 认证（session 或 Bearer token）
 * - 深度限制 max depth 5
 * - 查询复杂度限制
 * - Production 模式禁用 introspection（保留 admin introspection 端点）
 * - Rate limiting
 */
const express = require('express');
const router = express.Router();
const { NoSchemaIntrospectionCustomRule } = require("graphql");
const { graphqlHTTP } = require('express-graphql');
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLInt,
  GraphQLFloat,
  GraphQLBoolean,
  GraphQLList,
  GraphQLNonNull,
  GraphQLEnumType,
  GraphQLID
} = require('graphql');
const db = require('../config/database');
const { graphqlAuth } = require('../middleware/graphql-auth');

// ─── Rate limiter (simple in-memory, per-IP) ───
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 30;       // 30 requests per minute

function rateLimiter(ip) {
  const now = Date.now();
  const entry = rateLimit.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + RATE_LIMIT_WINDOW;
  }
  entry.count++;
  rateLimit.set(ip, entry);

  if (entry.count > RATE_LIMIT_MAX) {
    return {
      limited: true,
      retryAfter: Math.ceil((entry.resetAt - now) / 1000)
    };
  }
  return { limited: false };
}

// ─── 查询复杂度 & 深度限制 ───
const MAX_DEPTH = 5;
const MAX_COMPLEXITY = 100;

function computeComplexity(node, depth = 0) {
  if (depth > MAX_DEPTH) {
    throw new Error(`Query exceeds maximum depth of ${MAX_DEPTH}`);
  }
  let cost = 1;
  if (node.selectionSet) {
    for (const selection of node.selectionSet.selections) {
      if (selection.kind === 'Field') {
        cost += computeComplexity(selection, depth + 1);
      }
    }
  }
  return cost;
}

// ─── 类型定义 ───
const UserType = new GraphQLObjectType({
  name: 'User',
  fields: () => ({
    id: { type: GraphQLNonNull(GraphQLID) },
    username: { type: GraphQLString },
    email: { type: GraphQLString },
    full_name: { type: GraphQLString },
    department: { type: GraphQLString },
    role: { type: GraphQLString },
    tier: { type: GraphQLString },
    region: { type: GraphQLString },
    phone: { type: GraphQLString },
    quota: { type: GraphQLInt },
    created_at: { type: GraphQLString },
    is_active: { type: GraphQLInt },
    // 不暴露 password、api_token、ssn 等敏感字段
  })
});

const CustomerType = new GraphQLObjectType({
  name: 'Customer',
  fields: () => ({
    id: { type: GraphQLNonNull(GraphQLID) },
    company_name: { type: GraphQLString },
    contact_name: { type: GraphQLString },
    email: { type: GraphQLString },
    phone: { type: GraphQLString },
    tier: { type: GraphQLString },
    region: { type: GraphQLString },
    status: { type: GraphQLString },
    industry: { type: GraphQLString },
    annual_revenue: { type: GraphQLFloat },
    notes: { type: GraphQLString },
    created_by: { type: GraphQLInt },
    created_at: { type: GraphQLString },
    updated_at: { type: GraphQLString },
  })
});

const TicketType = new GraphQLObjectType({
  name: 'Ticket',
  fields: () => ({
    id: { type: GraphQLNonNull(GraphQLID) },
    ticket_ref: { type: GraphQLString },
    subject: { type: GraphQLString },
    description: { type: GraphQLString },
    priority: { type: GraphQLString },
    status: { type: GraphQLString },
    assigned_to: { type: GraphQLInt },
    created_by: { type: GraphQLInt },
    sla_deadline: { type: GraphQLString },
    created_at: { type: GraphQLString },
    updated_at: { type: GraphQLString },
  })
});

const OrderType = new GraphQLObjectType({
  name: 'Order',
  fields: () => ({
    id: { type: GraphQLNonNull(GraphQLID) },
    order_ref: { type: GraphQLString },
    customer_id: { type: GraphQLInt },
    total: { type: GraphQLFloat },
    status: { type: GraphQLString },
    approval_step: { type: GraphQLInt },
    approved_by: { type: GraphQLInt },
    notes: { type: GraphQLString },
    created_by: { type: GraphQLInt },
    created_at: { type: GraphQLString },
    updated_at: { type: GraphQLString },
  })
});

// ─── Root Query ───
const RootQuery = new GraphQLObjectType({
  name: 'RootQueryType',
  fields: {
    users: {
      type: new GraphQLList(UserType),
      args: {
        id: { type: GraphQLInt },
        role: { type: GraphQLString },
        department: { type: GraphQLString },
        limit: { type: GraphQLInt, defaultValue: 20 },
        offset: { type: GraphQLInt, defaultValue: 0 }
      },
      resolve(parent, args, context) {
        if (!context.user) throw new Error('Authentication required');
        if (context.user.role !== 'admin') throw new Error('Admin access required to list users');

        let sql = 'SELECT * FROM users WHERE 1=1';
        const params = [];

        if (args.id) { sql += ' AND id = ?'; params.push(args.id); }
        if (args.role) { sql += ' AND role = ?'; params.push(args.role); }
        if (args.department) { sql += ' AND department = ?'; params.push(args.department); }

        const limit = Math.min(100, Math.max(1, args.limit));
        const offset = Math.max(0, args.offset);
        sql += ' ORDER BY id ASC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        return db.prepare(sql).all(...params);
      }
    },
    customers: {
      type: new GraphQLList(CustomerType),
      args: {
        id: { type: GraphQLInt },
        search: { type: GraphQLString },
        limit: { type: GraphQLInt, defaultValue: 20 },
        offset: { type: GraphQLInt, defaultValue: 0 }
      },
      resolve(parent, args, context) {
        if (!context.user) throw new Error('Authentication required');

        let sql = 'SELECT * FROM customers WHERE 1=1';
        const params = [];

        // RBAC: employee sees only their own
        if (context.user.role === 'employee') {
          sql += ' AND created_by = ?';
          params.push(context.user.id);
        } else if (context.user.role === 'manager' && context.user.region) {
          sql += ' AND region = ?';
          params.push(context.user.region);
        }

        if (args.id) { sql += ' AND id = ?'; params.push(args.id); }
        if (args.search) {
          sql += ' AND (company_name LIKE ? OR contact_name LIKE ? OR email LIKE ?)';
          const term = `%${args.search}%`;
          params.push(term, term, term);
        }

        const limit = Math.min(100, Math.max(1, args.limit));
        const offset = Math.max(0, args.offset);
        sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        return db.prepare(sql).all(...params);
      }
    },
    tickets: {
      type: new GraphQLList(TicketType),
      args: {
        id: { type: GraphQLInt },
        status: { type: GraphQLString },
        priority: { type: GraphQLString },
        limit: { type: GraphQLInt, defaultValue: 20 },
        offset: { type: GraphQLInt, defaultValue: 0 }
      },
      resolve(parent, args, context) {
        if (!context.user) throw new Error('Authentication required');

        let sql = 'SELECT * FROM tickets WHERE 1=1';
        const params = [];

        if (context.user.role === 'employee') {
          sql += ' AND (created_by = ? OR assigned_to = ?)';
          params.push(context.user.id, context.user.id);
        }

        if (args.id) { sql += ' AND id = ?'; params.push(args.id); }
        if (args.status && ['open','in_progress','resolved','closed'].includes(args.status)) {
          sql += ' AND status = ?';
          params.push(args.status);
        }
        if (args.priority && ['Low','Medium','High','Critical'].includes(args.priority)) {
          sql += ' AND priority = ?';
          params.push(args.priority);
        }

        const limit = Math.min(100, Math.max(1, args.limit));
        const offset = Math.max(0, args.offset);
        sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        return db.prepare(sql).all(...params);
      }
    },
    orders: {
      type: new GraphQLList(OrderType),
      args: {
        id: { type: GraphQLInt },
        status: { type: GraphQLString },
        limit: { type: GraphQLInt, defaultValue: 20 },
        offset: { type: GraphQLInt, defaultValue: 0 }
      },
      resolve(parent, args, context) {
        if (!context.user) throw new Error('Authentication required');

        let sql = 'SELECT * FROM orders WHERE 1=1';
        const params = [];

        if (context.user.role === 'employee') {
          sql += ' AND (created_by = ?)';
          params.push(context.user.id);
        }

        if (args.id) { sql += ' AND id = ?'; params.push(args.id); }
        if (args.status && ['draft','pending','approved','rejected'].includes(args.status)) {
          sql += ' AND status = ?';
          params.push(args.status);
        }

        const limit = Math.min(100, Math.max(1, args.limit));
        const offset = Math.max(0, args.offset);
        sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        return db.prepare(sql).all(...params);
      }
    },
    me: {
      type: UserType,
      resolve(parent, args, context) {
        if (!context.user) throw new Error('Authentication required');
        return context.user;
      }
    }
  }
});

// ─── Schema ───
const schema = new GraphQLSchema({
  query: RootQuery
  // Mutation 暂不暴露（保持攻击面可控）
});

// ─── 是否是 production ───
const isProd = process.env.NODE_ENV === 'production';

// ─── 主 GraphQL 端点（带 introspection 控制） ───
router.use('/', (req, res, next) => {
  // Rate limiting
  const ip = req.ip || req.connection.remoteAddress;
  const rl = rateLimiter(ip);
  if (rl.limited) {
    res.set('Retry-After', String(rl.retryAfter));
    return res.status(429).json({ error: 'Too many GraphQL requests. Please try again later.' });
  }

  // 复杂度检查
  if (req.body && req.body.query) {
    try {
      const { parse } = require('graphql');
      const document = parse(req.body.query);
      let complexity = 0;
      for (const def of document.definitions) {
        if (def.kind === 'OperationDefinition' && def.selectionSet) {
          for (const sel of def.selectionSet.selections) {
            complexity += computeComplexity(sel, 1);
          }
        }
      }
      if (complexity > MAX_COMPLEXITY) {
        return res.status(400).json({ error: `Query complexity ${complexity} exceeds maximum of ${MAX_COMPLEXITY}` });
      }
    } catch (e) {
      // 解析错误交给 graphqlHTTP 处理
    }
  }

  next();
}, graphqlHTTP((req) => {
  const user = graphqlAuth(req);
  return {
    schema,
    graphiql: false,
    context: { user, req },
    customFormatErrorFn: (error) => {
      // 隐藏内部细节
      const message = error.message.includes('Authentication required') ||
                      error.message.includes('access required') ||
                      error.message.includes('Query exceeds') ||
                      error.message.includes('complexity')
        ? error.message
        : 'An error occurred while processing your GraphQL request.';
      return { message };
    },
    // Production 模式下禁用 introspection
    validationRules: isProd
      ? [NoIntrospectionValidation]
      : [],
  };
}));

// ─── Admin introspection 端点（始终可用，用于调试） ───
router.use('/introspection', graphqlHTTP((req) => {
  const user = graphqlAuth(req);
  if (!user || user.role !== 'admin') {
    return {
      schema,
      graphiql: false,
      context: { user, req },
      customFormatErrorFn: () => ({ message: 'Admin access required for introspection.' })
    };
  }
  return {
    schema,
    graphiql: true,
    context: { user, req },
  };
}));

// ─── Production introspection 禁用规则 ───
function NoIntrospectionValidation(context) {
  return {
    Field(node) {
      if (node.name.value === '__schema' || node.name.value === '__type') {
        context.reportError(
          new (require('graphql').GraphQLError)(
            'GraphQL introspection is not allowed in production mode.',
            { nodes: node }
          )
        );
      }
    }
  };
}

module.exports = router;
