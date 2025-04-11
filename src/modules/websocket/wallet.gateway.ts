import {
  SubscribeMessage,
  WebSocketGateway,
  OnGatewayInit,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import {
  BadRequestException,
  Inject,
  OnModuleInit,
  forwardRef,
  Logger,
} from '@nestjs/common';
import { Socket, Server } from 'socket.io';
import { AiService } from '../business/services/ai.service';
const SOCKET_PORT = Number(process.env.SOCKET_PORT) || 9000;
@WebSocketGateway({
  namespace: 'wallet',
  cors: {
    origin: '*',
  },
  maxHttpBufferSize: 1e8,
})
export class WalletGateway
  implements
    OnGatewayInit,
    OnGatewayConnection,
    OnGatewayDisconnect,
    OnModuleInit
{
  private readonly logger = new Logger(WalletGateway.name);

  @WebSocketServer() wss: Server;

  // Store recently emitted data and emission timestamps
  private lastEmittedData: Map<string, { data: any; timestamp: number }> =
    new Map();

  // Cleanup interval for lastEmittedData (in milliseconds)
  private readonly CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

  // Maximum age of data to keep (in milliseconds)
  private readonly MAX_DATA_AGE = 24 * 60 * 60 * 1000; // 24 hours

  // Cleanup interval reference
  private cleanupInterval: NodeJS.Timeout;

  // Wallet instance if needed
  private walletInstances: Map<string, any> = new Map();

  // Store handlers by clientId
  private clientHandlers: Map<
    string,
    (event: string, data: any, callback: Function) => void
  > = new Map();

  // Store mapping between UUID and client.id
  private uuidToClientId: Map<string, string> = new Map();
  private clientIdToUuid: Map<string, string> = new Map();

  @Inject(forwardRef(() => AiService))
  private readonly aiService: AiService;

  onModuleInit() {
    // Start the cleanup interval when the module initializes
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldData();
    }, this.CLEANUP_INTERVAL);
  }

  // Cleanup old data from the lastEmittedData map
  private cleanupOldData() {
    try {
      const now = Date.now();
      let cleanedCount = 0;

      for (const [key, value] of this.lastEmittedData.entries()) {
        if (now - value.timestamp > this.MAX_DATA_AGE) {
          this.lastEmittedData.delete(key);
          cleanedCount++;
        }
      }

      console.log(
        `Cleaned up ${cleanedCount} old entries from lastEmittedData`,
      );
    } catch (error) {
      console.error('Error during data cleanup:', error);
    }
  }

  afterInit(server: Server) {
    this.logger.log('🔌 Wallet Gateway Initialized');
    this.wss = server;

    // Set up error handling for the server
    server.on('error', (err) => {
      console.error('🔴 WebSocket server error:', err);
    });
  }

  handleConnection(client: Socket, ...args: any[]) {
    console.log(`✅ Client connected: ${client.id}`);

    // Get UUID from query params if available
    const threadId = client.handshake.query.thread_id as string;

    if (threadId) {
      console.log(`✅ Client UUID provided: ${threadId}`);
      // Save mapping between UUID and client.id
      this.uuidToClientId.set(threadId, client.id);
      this.clientIdToUuid.set(client.id, threadId);
      this.aiService.subscribeWallet(threadId, client);
    }

    // Notify client of successful connection
    client.emit('connection_established', {
      status: 'connected',
      clientId: client.id,
      threadId: threadId || null,
    });

    // Set up error handling for each client
    client.on('error', (err) => {
      console.error(`🔴 Error from client ${client.id}:`, err);
    });

    // Set up disconnect handling
    client.on('disconnect', (reason) => {
      console.log(`🔴 Client ${client.id} disconnected: ${reason}`);

      // Delete mapping when client disconnects
      const clientUuid = this.clientIdToUuid.get(client.id);
      if (clientUuid) {
        this.uuidToClientId.delete(clientUuid);
        this.clientIdToUuid.delete(client.id);
      }

      // Cleanup any wallet instances for this client
      this.walletInstances.delete(client.id);
      this.clientHandlers.delete(client.id);
    });
  }

  handleDisconnect(client: Socket) {
    console.log(`🔴 Client disconnected: ${client.id}`);

    // Delete mapping when client disconnects
    const clientUuid = this.clientIdToUuid.get(client.id);
    if (clientUuid) {
      this.uuidToClientId.delete(clientUuid);
      this.clientIdToUuid.delete(client.id);
    }

    // Cleanup any resources associated with this client
    this.walletInstances.delete(client.id);
    this.clientHandlers.delete(client.id);
  }

  // Method to get client.id from UUID
  getClientIdFromUuid(uuid: string): string | null {
    return this.uuidToClientId.get(uuid) || null;
  }

  // Method to get UUID from client.id
  getUuidFromClientId(clientId: string): string | null {
    return this.clientIdToUuid.get(clientId) || null;
  }

  /**
   * Get wallet address for a specific threadId
   * @param threadId The threadId to get address for
   * @param network The network to get address for
   * @returns Promise with the wallet address
   */
  async getWalletAddress(threadId: string, network: string): Promise<string> {
    try {
      console.log('🔍 Getting wallet address for threadId:', {
        x: this.uuidToClientId,
        y: this.clientIdToUuid,
      });

      const clientId = this.uuidToClientId.get(threadId);
      if (!clientId) {
        throw new BadRequestException(
          'No active connection found for this threadId',
        );
      }

      return new Promise((resolve, reject) => {
        // Check if this.wss exists
        if (!this.wss) {
          this.logger.error('WebSocket server is not initialized');
          reject(
            new BadRequestException('WebSocket server is not initialized'),
          );
          return;
        }

        // Use async/await with fetchSockets
        this.wss.fetchSockets().then((sockets) => {
          const socket = sockets.find((s) => s.id === clientId);
          
          if (!socket) {
            this.logger.error(`Socket with ID ${clientId} not found`);
            reject(new BadRequestException('Socket not found'));
            return;
          }

          // Create a timeout to ensure callback will be called
          let timeoutId = setTimeout(() => {
            this.logger.warn('Get address timeout - using fallback address');
            resolve('0x1234567890123456789012345678901234567890'); // Default address
          }, 5000); // Timeout after 5 seconds
  
          // Use callback to get wallet address
          socket.emit('get_address', { network }, (response) => {
            clearTimeout(timeoutId); // Clear timeout if callback is called
            
            if (response && response.address) {
              resolve(response.address);
            } else {
              reject(new BadRequestException('Failed to get wallet address'));
            }
          });
        }).catch((err) => {
          this.logger.error('Error fetching sockets:', err);
          reject(new BadRequestException('Error fetching sockets'));
        });
      });
    } catch (error) {
      this.logger.error(
        `🔴 Error getting wallet address for threadId ${threadId}:`,
        error,
      );
      throw error;
    }
  }

  async testSignMessage(threadId: string, message: string): Promise<string> {
    try {
      console.log('🔍 Signing message for threadId:', {
        x: this.uuidToClientId,
        y: this.clientIdToUuid,
      });

      const clientId = this.uuidToClientId.get(threadId);
      if (!clientId) {
        throw new BadRequestException(
          'No active connection found for this threadId',
        );
      }

      return new Promise((resolve, reject) => {
        if (!this.wss) {
          this.logger.error('WebSocket server is not initialized');
          reject(
            new BadRequestException('WebSocket server is not initialized'),
          );
          return;
        }

        this.wss.fetchSockets().then((sockets) => {
          const socket = sockets.find((s) => s.id === clientId);
          
          if (!socket) {
            this.logger.error(`Socket with ID ${clientId} not found`);
            reject(new BadRequestException('Socket not found'));
            return;
          }

          socket.emit('sign_message', { message }, (response) => {
            console.log('🔍 Sign message response:', response);
            if (response && response.signature) {
              resolve(response.signature);
            } else {
              reject(new BadRequestException('Failed to sign message'));
            }
          });
        }).catch((err) => {
          this.logger.error('Error fetching sockets:', err);
          reject(new BadRequestException('Error fetching sockets'));
        });
      });
    } catch (error) {
      this.logger.error(
        `🔴 Error signing message for threadId ${threadId}:`,
        error,
      );
      throw error;
    }
  }

  async testSignTransaction(threadId: string): Promise<string> {
    try {
      // console.log('🔍 Signing transaction for threadId:', {
      //   x: this.uuidToClientId,
      //   y: this.clientIdToUuid,
      // });

      const clientId = this.uuidToClientId.get(threadId);
      if (!clientId) {
        throw new BadRequestException(
          'No active connection found for this threadId',
        );
      }

      return new Promise((resolve, reject) => {
        if (!this.wss) {
          this.logger.error('WebSocket server is not initialized');
          reject(
            new BadRequestException('WebSocket server is not initialized'),
          );
          return;
        }

        this.wss.fetchSockets().then((sockets) => {
          const socket = sockets.find((s) => s.id === clientId);
          
          if (!socket) {
            this.logger.error(`Socket with ID ${clientId} not found`);
            reject(new BadRequestException('Socket not found'));
            return;
          }

          socket.emit('sign_transaction', { }, (response) => {
            console.log('🔍 Sign transaction response:', response);
            if (response && response.signedTransaction) {
              resolve(response.signedTransaction);
            } else {
              reject(new BadRequestException('Failed to sign transaction'));
            }
          });
        }).catch((err) => {
          this.logger.error('Error fetching sockets:', err);
          reject(new BadRequestException('Error fetching sockets'));
        });
      });
    } catch (error) {
      this.logger.error(
        `🔴 Error signing transaction for threadId ${threadId}:`,
        error,
      );
      throw error;
    }
  }
}
