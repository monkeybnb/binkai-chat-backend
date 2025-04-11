import { Body, Controller, Post, UseGuards, UnauthorizedException, Param, Sse, Get, Query, Delete, HttpStatus } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { ThreadService } from '@/business/services';
import { 
  CreateThreadDto, 
  ThreadResponseDto, 
  StreamMessageDto, 
  ThreadListResponseDto,
  MessageListResponseDto
} from '@/api/dtos';
import { CurrentUserId } from '../decorator/user.decorator';
import { User } from '@/database/entities';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { PaginateDto } from '@/shared/pagination/paginate.dto';

@ApiTags('Thread')
@Controller('thread')
export class ThreadController {
  constructor(private readonly threadService: ThreadService) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Create a new thread' })
  @ApiResponse({
    status: 201,
    description: 'Thread created successfully',
    type: ThreadResponseDto
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized'
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request'
  })
  async createThread(
    @Body() createThreadDto: CreateThreadDto,
    @CurrentUserId() userId: string
  ) {
    try {
      console.log(`✅ [ThreadController] [createThread] createThreadDto:`, createThreadDto);
      console.log(`✅ [ThreadController] [createThread] userId:`, userId);
      
      if (!userId) {
        console.log(`🔴 [ThreadController] [createThread] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const thread = await this.threadService.createThread(userId, createThreadDto);
      
      console.log(`✅ [ThreadController] [createThread] thread created:`, thread);
      
      return thread;
    } catch (error) {
      console.log(`🔴 [ThreadController] [createThread] error:`, error);
      throw error;
    }
  }

  @Sse('stream-message')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Stream a message response from OpenAI for a given question and thread' })
  @ApiResponse({
    status: 200,
    description: 'Stream of message chunks from OpenAI GPT model',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized'
  })
  @ApiResponse({
    status: 404,
    description: 'Thread not found'
  })
  streamMessage(
    @Body() streamMessageDto: StreamMessageDto,
    @CurrentUserId() userId: string
  ): Observable<{ data: string }> {
    try {
      console.log(`✅ [ThreadController] [streamMessage] streamMessageDto:`, streamMessageDto);
      console.log(`✅ [ThreadController] [streamMessage] userId:`, userId);
      
      if (!userId) {
        console.log(`🔴 [ThreadController] [streamMessage] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      return this.threadService.streamMessage(
        userId, 
        streamMessageDto.thread_id, 
        streamMessageDto.question
      ).pipe(
        map(chunk => ({ data: chunk }))
      );
    } catch (error) {
      console.log(`🔴 [ThreadController] [streamMessage] error:`, error);
      throw error;
    }
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get list of threads for current user' })
  @ApiResponse({
    status: 200,
    description: 'List of threads retrieved successfully',
    type: ThreadListResponseDto
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized'
  })
  async getThreads(
    @CurrentUserId() userId: string,
    @Query() paginateDto: PaginateDto
  ) {
    try {
      console.log(`✅ [ThreadController] [getThreads] userId:`, userId);
      console.log(`✅ [ThreadController] [getThreads] paginateDto:`, paginateDto);
      
      if (!userId) {
        console.log(`🔴 [ThreadController] [getThreads] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const threads = await this.threadService.getThreadsByUserId(userId, paginateDto);
      
      console.log(`✅ [ThreadController] [getThreads] threads found:`, threads.pagination.total);
      
      return threads;
    } catch (error) {
      console.log(`🔴 [ThreadController] [getThreads] error:`, error);
      throw error;
    }
  }

  @Get(':threadId/messages')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get messages for a specific thread' })
  @ApiParam({
    name: 'threadId',
    description: 'ID of the thread to get messages from',
    type: String,
    required: true
  })
  @ApiResponse({
    status: 200,
    description: 'Messages retrieved successfully',
    type: MessageListResponseDto
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized'
  })
  @ApiResponse({
    status: 404,
    description: 'Thread not found or not owned by user'
  })
  async getThreadMessages(
    @Param('threadId') threadId: string,
    @CurrentUserId() userId: string,
    @Query() paginateDto: PaginateDto
  ) {
    try {
      // console.log(`✅ [ThreadController] [getThreadMessages] threadId:`, threadId);
      // console.log(`✅ [ThreadController] [getThreadMessages] userId:`, userId);
      // console.log(`✅ [ThreadController] [getThreadMessages] paginateDto:`, paginateDto);
      
      if (!userId) {
        console.log(`🔴 [ThreadController] [getThreadMessages] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const messages = await this.threadService.getMessagesByThreadId(userId, threadId, paginateDto);
      
      // console.log(`✅ [ThreadController] [getThreadMessages] messages found:`, messages.pagination.total);
      
      return messages;
    } catch (error) {
      console.log(`🔴 [ThreadController] [getThreadMessages] error:`, error);
      throw error;
    }
  }

  @Delete(':threadId')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete a thread' })
  @ApiParam({
    name: 'threadId',
    description: 'ID of the thread to delete',
    type: String,
    required: true
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Thread deleted successfully'
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized'
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Thread not found or not owned by user'
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Bad request'
  })
  async deleteThread(
    @Param('threadId') threadId: string,
    @CurrentUserId() userId: string
  ) {
    try {
      console.log(`✅ [ThreadController] [deleteThread] threadId:`, threadId);
      console.log(`✅ [ThreadController] [deleteThread] userId:`, userId);
      
      if (!userId) {
        console.log(`🔴 [ThreadController] [deleteThread] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const result = await this.threadService.deleteThread(userId, threadId);
      
      console.log(`✅ [ThreadController] [deleteThread] thread deleted:`, result);
      
      return { success: true, message: 'Thread deleted successfully' };
    } catch (error) {
      console.log(`🔴 [ThreadController] [deleteThread] error:`, error);
      throw error;
    }
  }
} 