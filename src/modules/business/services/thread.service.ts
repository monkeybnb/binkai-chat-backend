import { Injectable, UnauthorizedException, NotFoundException, BadRequestException } from '@nestjs/common';
import { ThreadRepository } from '../../database/repositories';
import { MessageRepository } from '../../database/repositories';
import { CreateThreadDto } from '@/api/dtos';
import { Thread, Message } from '../../database/entities';
import { Observable } from 'rxjs';
import { PaginateDto } from '@/shared/pagination/paginate.dto';
import { IGetPaginationResponse, paginate } from '@/shared/pagination/pagination';
import { OpenAIService } from './openai.service';
import { map, tap } from 'rxjs/operators';
import { AiService } from './ai.service';
// Import EventEmitter from Node.js
import { EventEmitter } from 'events';

@Injectable()
export class ThreadService {
  constructor(
    private readonly threadRepository: ThreadRepository,
    private readonly messageRepository: MessageRepository,
    private readonly openAIService: OpenAIService,
    private readonly aiService: AiService
  ) {}

  /**
   * Create a new thread
   * @param userId - ID of the user creating the thread
   * @param createThreadDto - Data for creating the thread 
   * @returns The created thread
   */
  async createThread(userId: string, createThreadDto: CreateThreadDto): Promise<Thread> {
    try {
      console.log(`✅ [ThreadService] [createThread] createThreadDto:`, createThreadDto);
      console.log(`✅ [ThreadService] [createThread] userId:`, userId);
      
      if (!userId) {
        console.log(`🔴 [ThreadService] [createThread] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const thread = new Thread();
      thread.title = createThreadDto.title || 'New Thread';
      thread.user_id = userId;
      
      const savedThread = await this.threadRepository.save(thread);
      console.log(`✅ [ThreadService] [createThread] savedThread:`, savedThread);
      
      return savedThread;
    } catch (error) {
      console.log(`🔴 [ThreadService] [createThread] error:`, error);
      throw error;
    }
  }

  /**
   * Stream a message response based on a question and thread ID
   * @param userId - ID of the user requesting the stream
   * @param threadId - ID of the thread
   * @param question - The question to process
   * @returns Observable stream of text chunks
   */
  streamMessage(userId: string, threadId: string, question: string): Observable<string> {
    return new Observable<string>(observer => {
      try {
        console.log(`✅ [ThreadService] [streamMessage] threadId:`, threadId);
        console.log(`✅ [ThreadService] [streamMessage] userId:`, userId);
        console.log(`✅ [ThreadService] [streamMessage] question:`, question);
        
        if (!userId) {
          console.log(`🔴 [ThreadService] [streamMessage] userId is null or undefined`);
          observer.error(new UnauthorizedException('User not authenticated properly'));
          return;
        }

        // Store userMessage reference for later use with the AI reply
        let userMessage: Message;
        // Save reference to EventEmitter for cleanup when needed
        let emitter: EventEmitter;
        // Setup timeout
        const timeoutId = setTimeout(() => {
          console.log(`⚠️ [ThreadService] [streamMessage] Stream timeout after 60 seconds`);
          if (emitter) {
            emitter.removeAllListeners();
          }
          observer.error(new Error('Stream timeout after 60 seconds'));
        }, 60000); // Timeout after 60 seconds

        // Verify thread exists and belongs to user
        this.threadRepository.findOne({ where: { id: threadId, user_id: userId } })
          .then(async thread => {
            if (!thread) {
              console.log(`🔴 [ThreadService] [streamMessage] Thread not found or not owned by user`);
              observer.error(new Error('Thread not found or not owned by user'));
              clearTimeout(timeoutId);
              return;
            }

            // Save user's question to database
            userMessage = new Message();
            userMessage.thread_id = threadId;
            userMessage.user_id = userId;
            userMessage.content = question;
            userMessage.is_ai = false; // Explicitly set as user message
            userMessage.parent_id = null; // User questions don't have parents
            
            try {
              userMessage = await this.messageRepository.save(userMessage);
              console.log(`✅ [ThreadService] [streamMessage] User message saved:`, userMessage.id);
            } catch (error) {
              console.log(`🔴 [ThreadService] [streamMessage] Error saving user message:`, error);
              // Continue with the stream even if saving fails
            }

            // Get message history from this thread (limit to 10 most recent messages)
            const messageHistory = await this.messageRepository.find({
              where: { thread_id: threadId },
              order: { created_at: 'DESC' },
              take: 10
            });
            
            // Reverse to get the correct order (old to new)
            const orderedMessages = messageHistory.reverse();
            
            // Prepare messages for OpenAI API
            const messages: Array<{ role: 'user' | 'system' | 'assistant'; content: string }> = [
            ];
            
            // Add message history (except current message)
            for (const msg of orderedMessages) {
              // Skip current message
              if (msg.id === userMessage?.id) continue;
              
              messages.push({
                role: msg.is_ai ? 'assistant' : 'user',
                content: msg.content
              });
            }
            
            // Add current user message
            messages.push({
              role: 'user',
              content: question
            });

            console.log(`🔍 [ThreadService] [streamMessage] Sending ${messages.length} messages to AI`);
            
            // Use aiService.streamChatCompletion with message history
//             this.aiService.streamChatCompletion(messages)
//               .then(eventEmitter => {
//                 // Save reference for cleanup
//                 emitter = eventEmitter;
                
//                 // Variables to collect full response
//                 let responseContent = '';
                
//                 // Handle data chunks
//                 emitter.on('data', (chunk: string) => {
//                   responseContent += chunk;
//                   observer.next(chunk);
//                 });

//                 // Handle errors
//                 emitter.on('error', (error) => {
//                   console.log(`🔴 [ThreadService] [streamMessage] AI stream error:`, error);
//                   clearTimeout(timeoutId);
//                   observer.error(error);
//                 });

//                 // Handle completion
//                 emitter.on('end', async (finalText: string) => {
//                   clearTimeout(timeoutId);
                  
//                   // Save AI response to database after stream is complete
//                   const aiMessage = new Message();
//                   aiMessage.thread_id = threadId;
//                   aiMessage.user_id = userId; // Keep the user ID for attribution
//                   aiMessage.content = finalText; // Use finalText from end event
//                   aiMessage.is_ai = true; // Mark as AI message
//                   aiMessage.parent_id = userMessage?.id || null; // Link to the user's message
                  
//                   console.log(`📝 [ThreadService] [streamMessage] Full AI response: 
// ----- AI RESPONSE START -----
// ${finalText}
// ----- AI RESPONSE END -----`);
                  
//                   try {
//                     await this.messageRepository.save(aiMessage);
//                     console.log(`✅ [ThreadService] [streamMessage] AI message saved:`, aiMessage.id);
//                   } catch (error) {
//                     console.log(`🔴 [ThreadService] [streamMessage] Error saving AI message:`, error);
//                   } finally {
//                     observer.complete();
//                   }
//                 });
//               })
//               .catch(error => {
//                 console.log(`🔴 [ThreadService] [streamMessage] Error initializing AI stream:`, error);
//                 clearTimeout(timeoutId);
//                 observer.error(error);
//               });
          })
          .catch(error => {
            console.log(`🔴 [ThreadService] [streamMessage] error:`, error);
            clearTimeout(timeoutId);
            observer.error(error);
          });
          
        // Cleanup when client disconnects
        return () => {
          console.log(`✅ [ThreadService] [streamMessage] Client disconnected, cleaning up`);
          clearTimeout(timeoutId);
          if (emitter) {
            emitter.removeAllListeners();
          }
        };
      } catch (error) {
        console.log(`🔴 [ThreadService] [streamMessage] error:`, error);
        observer.error(error);
      }
    });
  }

  /**
   * Get threads for a specific user with pagination
   * @param userId - ID of the user
   * @param paginateDto - Pagination parameters
   * @returns Paginated threads
   */
  async getThreadsByUserId(
    userId: string,
    paginateDto: PaginateDto,
  ): Promise<IGetPaginationResponse<Thread[]>> {
    try {
      console.log(`✅ [ThreadService] [getThreadsByUserId] userId:`, userId);
      console.log(`✅ [ThreadService] [getThreadsByUserId] paginateDto:`, paginateDto);
      
      if (!userId) {
        console.log(`🔴 [ThreadService] [getThreadsByUserId] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      const queryBuilder = this.threadRepository
        .createQueryBuilder('thread')
        .where('thread.user_id = :userId', { userId })
        .orderBy(
          paginateDto.sort_field ? `thread.${paginateDto.sort_field}` : 'thread.created_at',
          paginateDto.sort_type,
        );
      
      const result = await paginate(queryBuilder, paginateDto.page, paginateDto.take);
      console.log(`✅ [ThreadService] [getThreadsByUserId] total threads:`, result.pagination.total);
      
      return result;
    } catch (error) {
      console.log(`🔴 [ThreadService] [getThreadsByUserId] error:`, error);
      throw error;
    }
  }

  /**
   * Get messages for a specific thread with pagination
   * @param userId - ID of the user requesting messages
   * @param threadId - ID of the thread
   * @param paginateDto - Pagination parameters
   * @returns Paginated messages
   */
  async getMessagesByThreadId(
    userId: string,
    threadId: string,
    paginateDto: PaginateDto,
  ): Promise<IGetPaginationResponse<Message[]>> {
    try {
      console.log(`✅ [ThreadService] [getMessagesByThreadId] userId:`, userId);
      console.log(`✅ [ThreadService] [getMessagesByThreadId] threadId:`, threadId);
      console.log(`✅ [ThreadService] [getMessagesByThreadId] paginateDto:`, paginateDto);
      
      if (!userId) {
        console.log(`🔴 [ThreadService] [getMessagesByThreadId] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      // Verify thread exists and belongs to user
      const thread = await this.threadRepository.findOne({ 
        where: { id: threadId, user_id: userId } 
      });
      
      if (!thread) {
        console.log(`🔴 [ThreadService] [getMessagesByThreadId] Thread not found or not owned by user`);
        throw new Error('Thread not found or not owned by user');
      }
      
      const queryBuilder = this.messageRepository
        .createQueryBuilder('message')
        .where('message.thread_id = :threadId', { threadId })
        .orderBy(
          paginateDto.sort_field ? `message.${paginateDto.sort_field}` : 'message.created_at',
          paginateDto.sort_type,
        );
      
      const result = await paginate(queryBuilder, paginateDto.page, paginateDto.take);
      console.log(`✅ [ThreadService] [getMessagesByThreadId] total messages:`, result.pagination.total);
      
      return result;
    } catch (error) {
      console.log(`🔴 [ThreadService] [getMessagesByThreadId] error:`, error);
      throw error;
    }
  }

  /**
   * Delete a thread and all its messages
   * @param userId - ID of the user requesting deletion
   * @param threadId - ID of the thread to delete
   * @returns Object indicating success
   */
  async deleteThread(userId: string, threadId: string): Promise<{ success: boolean }> {
    try {
      console.log(`✅ [ThreadService] [deleteThread] userId:`, userId);
      console.log(`✅ [ThreadService] [deleteThread] threadId:`, threadId);
      
      if (!userId) {
        console.log(`🔴 [ThreadService] [deleteThread] userId is null or undefined`);
        throw new UnauthorizedException('User not authenticated properly');
      }
      
      // Verify thread exists and belongs to user
      const thread = await this.threadRepository.findOne({ 
        where: { id: threadId, user_id: userId } 
      });
      
      if (!thread) {
        console.log(`🔴 [ThreadService] [deleteThread] Thread not found or not owned by user`);
        throw new NotFoundException('Thread not found or not owned by user');
      }
      
      // Delete all messages first
      await this.messageRepository.delete({ thread_id: threadId });
      console.log(`✅ [ThreadService] [deleteThread] Messages deleted for thread:`, threadId);
      
      // Then delete the thread
      await this.threadRepository.delete({ id: threadId });
      console.log(`✅ [ThreadService] [deleteThread] Thread deleted:`, threadId);
      
      return { success: true };
    } catch (error) {
      console.log(`🔴 [ThreadService] [deleteThread] error:`, error);
      throw error;
    }
  }

  /**
   * Get existing thread or create a new one if needed
   * @param userId - ID of the user
   * @param threadId - Optional thread ID to find
   * @returns ID of the thread (existing or newly created)
   */
  async getOrCreateThread(userId: string, threadId?: string): Promise<string> {
    // If threadId exists, check and validate
    if (threadId) {
      const thread = await this.threadRepository.findOne({ 
        where: { id: threadId, user_id: userId } 
      });
      
      if (!thread) {
        console.log(`🔴 [ThreadService] [getOrCreateThread] Thread not found or not owned by user`);
        throw new BadRequestException('Thread not found or not owned by user');
      }
      
      return threadId;
    }
    
    // If no threadId, create a new thread
    const newThreadId = crypto.randomUUID();
    const thread = new Thread();
    thread.id = newThreadId;
    thread.title = 'New Thread';
    thread.user_id = userId;
    
    await this.threadRepository.save(thread);
    console.log(`✅ [ThreadService] [getOrCreateThread] New thread created:`, newThreadId);
    
    return newThreadId;
  }

  /**
   * Save message to database
   * @param params - Object containing message data
   * @returns The saved message entity
   */
  async saveMessage(params: {
    threadId: string;
    userId: string;
    content: string;
    isAi: boolean;
    parentId: string | null;
  }): Promise<Message> {
    const { threadId, userId, content, isAi, parentId } = params;
    
    const message = new Message();
    message.thread_id = threadId;
    message.user_id = userId;
    message.content = content;
    message.is_ai = isAi;
    message.parent_id = parentId;
    
    const savedMessage = await this.messageRepository.save(message);
    console.log(`✅ [ThreadService] [saveMessage] ${isAi ? 'AI' : 'User'} message saved:`, savedMessage.id);
    
    return savedMessage;
  }
} 