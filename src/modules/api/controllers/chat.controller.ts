import { Controller, Post, Body, UseGuards, UnauthorizedException, BadRequestException, Res, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Response } from 'express';

import { ChatRequestDto, ChatResponseDto } from '../dtos/chat.dto';
import { AiService } from '../../business/services/ai.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUserId } from '../decorator/user.decorator';
import { ThreadService } from '../../business/services/thread.service';

@ApiTags('Chat')
@Controller('chat')
export class ChatController {
  constructor(
    private readonly aiService: AiService,
    private readonly threadService: ThreadService
  ) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Send a message to AI and get response' })
  @ApiResponse({
    status: 200,
    description: 'AI response received successfully',
    type: ChatResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async chat(
    @Body() chatRequestDto: ChatRequestDto,
    @CurrentUserId() userId: string,
  ): Promise<ChatResponseDto> {
    try {
      console.log(`✅ [ChatController] [chat] chatRequestDto:`, chatRequestDto);
      
      if (!userId) {
        console.log(`🔴 [ChatController] [chat] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }

      // Get or create thread using ThreadService
      const threadId = await this.threadService.getOrCreateThread(userId, chatRequestDto.threadId);
      
      // Save user message using ThreadService
      const userMessage = await this.threadService.saveMessage({
        threadId,
        userId,
        content: chatRequestDto.message,
        isAi: false,
        parentId: null
      });
      
      // Get response from AI
      const response = await this.aiService.handleAgent(threadId, chatRequestDto.message);
      
      // Save AI response using ThreadService
      await this.threadService.saveMessage({
        threadId,
        userId,
        content: response,
        isAi: true,
        parentId: userMessage.id
      });

      return { response, threadId };
    } catch (error) {
      console.log(`🔴 [ChatController] [chat] error:`, error);
      throw new BadRequestException(error.message);
    }
  }

  @Post('stream')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Stream AI response in real-time' })
  @ApiResponse({
    status: 200,
    description: 'AI response streamed successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async streamChat(
    @Body() chatRequestDto: ChatRequestDto,
    @CurrentUserId() userId: string,
    @Res() response: Response,
  ): Promise<void> {
    try {
      // console.log(`✅ [ChatController] [streamChat] chatRequestDto:`, chatRequestDto);
      
      if (!userId) {
        console.log(`🔴 [ChatController] [streamChat] userId is null or undefined`);
        response.status(HttpStatus.UNAUTHORIZED).send({ message: 'User not authenticated properly' });
        return;
      }

      // Get or create thread
      const threadId = await this.threadService.getOrCreateThread(userId, chatRequestDto.threadId);

      // Save user message using ThreadService
      const userMessage = await this.threadService.saveMessage({
        threadId,
        userId,
        content: chatRequestDto.message,
        isAi: false,
        parentId: null
      });

      // Set SSE headers
      response.setHeader('Content-Type', 'text/event-stream');
      response.setHeader('Cache-Control', 'no-cache');
      response.setHeader('Connection', 'keep-alive');
      response.setHeader('X-Accel-Buffering', 'no'); // Disable Nginx buffering
      response.flushHeaders();

      // First send the threadId
      response.write(`data: ${JSON.stringify({ threadId })}\n\n`);

      // Create variables to store the complete AI response
      let fullAiResponse = '';

      // Subscribe to the stream from AiService instead of ThreadService
      const agentStream = this.aiService.handleAgentStream(threadId, chatRequestDto.message);
      
      // Set up subscription to stream
      const subscription = agentStream.subscribe({
        next: (chunk: string) => {
          // Accumulate the full response
          fullAiResponse += chunk;
          
          // Send each chunk as an SSE event
          response.write(`data: ${JSON.stringify({ content: chunk })}\n\n`);
        },
        error: (error) => {
          console.log(`🔴 [ChatController] [streamChat] Stream error:`, error);
          response.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
          response.end();
        },
        complete: async () => {
          console.log(`✅ [ChatController] [streamChat] Stream completed`);
          
          // Save the complete AI response
          // await this.threadService.saveMessage({
          //   threadId,
          //   userId,
          //   content: fullAiResponse,
          //   isAi: true,
          //   parentId: userMessage.id
          // });
          
          // Send completion event
          response.write(`data: ${JSON.stringify({ done: true })}\n\n`);
          response.end();
        }
      });

      // Handle client disconnect
      response.on('close', () => {
        console.log(`✅ [ChatController] [streamChat] Client disconnected, cleaning up`);
        subscription.unsubscribe();
        
        // Still save the partial response if it exists
        if (fullAiResponse) {
          console.log(`✅ [ChatController] [streamChat] Saving partial response:`, fullAiResponse);
          this.threadService.saveMessage({
            threadId,
            userId,
            content: fullAiResponse,
            isAi: true,
            parentId: userMessage.id
          }).catch(err => {
            console.log(`🔴 [ChatController] [streamChat] Error saving partial response:`, err);
          });
        }
      });
    } catch (error) {
      console.log(`🔴 [ChatController] [streamChat] error:`, error);
      if (!response.headersSent) {
        response.status(HttpStatus.BAD_REQUEST).send({ message: error.message });
      } else {
        response.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
        response.end();
      }
    }
  }
} 