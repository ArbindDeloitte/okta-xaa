// The HR Agent's AgentExecutor: the SDK calls execute() once per incoming message and expects exactly one
// `message` or `task` event published as the first event (see @a2a-js/sdk/dist/index.d.ts -- AgentExecutor).
// This agent never creates a Task: every call is answered as a single Message, which the SDK's request handler
// settles automatically once execute() returns (the "bare-Message stream pattern" -- no eventBus.finished() call
// needed, matching the SDK's own sample-agent and authentication samples).
import crypto from 'node:crypto';
import { AgentEvent, type AgentExecutor, type ExecutionEventBus, type RequestContext } from '@a2a-js/sdk/server';
import { Role, type Message } from '@a2a-js/sdk';
import { answerHrTask } from './llm.js';
import { VerifiedCaller } from './auth.js';

const textOf = (m: Message): string => m.parts.find((p) => p.content?.$case === 'text')?.content?.value ?? '';

const replyMessage = (text: string, ctx: RequestContext): Message => ({
  messageId: crypto.randomUUID(),
  role: Role.ROLE_AGENT,
  parts: [{ content: { $case: 'text', value: text }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
  taskId: ctx.taskId,
  contextId: ctx.contextId,
  extensions: [],
  metadata: undefined,
  referenceTaskIds: [],
});

export class HrAgentExecutor implements AgentExecutor {
  async execute(requestContext: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
    const caller = requestContext.context.user;
    if (!(caller instanceof VerifiedCaller) || !caller.isAuthenticated) {
      eventBus.publish(
        AgentEvent.message(replyMessage('Unauthorized: this agent requires a valid Okta-issued bearer token (Cross App Access, agent-to-agent).', requestContext)),
      );
      return;
    }
    const task = textOf(requestContext.userMessage).trim();
    if (!task) {
      eventBus.publish(AgentEvent.message(replyMessage('Empty request: send a text message describing what you need.', requestContext)));
      return;
    }
    try {
      const text = await answerHrTask(task, caller);
      eventBus.publish(AgentEvent.message(replyMessage(text, requestContext)));
    } catch (e) {
      console.error('[agent-hr] execute failed:', (e as Error).message);
      eventBus.publish(AgentEvent.message(replyMessage(`HR Agent error: ${(e as Error).message}`, requestContext)));
    }
  }

  async cancelTask(_taskId: string, _eventBus: ExecutionEventBus): Promise<void> {
    // This agent never creates a Task, so there is never anything in flight to cancel.
  }
}
