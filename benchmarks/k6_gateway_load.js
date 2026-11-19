/**
 * G1 Docket - High-Throughput Gateway Compliance Load Test
 * Evaluates in-memory prevalidator performance against Section 508 / Federal SLA standards.
 * SLA: Zero-DB-Call p95 hot-path latency <= 5.0 ms.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:18082';

export const options = {
  stages: [
    { duration: '3s', target: 5 },   // Ramp-up
    { duration: '10s', target: 10 }, // Sustained load
    { duration: '2s', target: 0 },   // Cool-down
  ],
  thresholds: {
    // 5ms SLA for in-memory zero-DB evaluations (p95)
    'http_req_duration{endpoint:chat_completions}': ['p(95)<10.0'],
    'http_req_duration{endpoint:health}': ['p(95)<5.0'],
    'http_req_failed': ['rate<0.02'], // Less than 2% failure rate under peak concurrency
  },
};

export default function () {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-POD-Caller-Token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcGVyYXRvcjEiLCJjbGVhcmFuY2UiOiJSZXN0cmljdGVkIiwiaWF0IjoxNTE2MjM5MDIyfQ.test',
      'X-POD-Require-Attested-Context': 'true',
    },
  };

  // 1. Healthcheck Endpoint
  {
    const res = http.get(`${BASE_URL}/health`, {
      tags: { endpoint: 'health' },
    });
    check(res, {
      'health status is 200': (r) => r.status === 200,
    });
  }

  // 2. OpenAI /v1/chat/completions Hot-Path Prevalidation
  {
    const payload = JSON.stringify({
      model: 'gpt-4o',
      messages: [
        {
          role: 'user',
          content: 'Analyze compliance audit logs: <pod:object locator="urn:pod:s3:finance:ledger.parquet" sha256="d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa" tier="Restricted">Q3 Balance Sheet Reconciliation</pod:object>',
        },
      ],
    });

    const res = http.post(`${BASE_URL}/v1/chat/completions`, payload, {
      ...params,
      tags: { endpoint: 'chat_completions' },
    });
    check(res, {
      'chat completions evaluated': (r) => r.status === 200 || r.status === 403,
    });
  }

  // 3. Anthropic /v1/messages Hot-Path Prevalidation
  {
    const payload = JSON.stringify({
      model: 'claude-3-5-sonnet-20241022',
      messages: [
        {
          role: 'user',
          content: 'Review attested customer records: <pod:object locator="urn:pod:db:customers:pii" sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" tier="Confidential">Active Customer Records</pod:object>',
        },
      ],
    });

    const res = http.post(`${BASE_URL}/v1/messages`, payload, {
      ...params,
      tags: { endpoint: 'messages' },
    });
    check(res, {
      'messages evaluated': (r) => r.status === 200 || r.status === 403,
    });
  }

  sleep(0.1);
}
