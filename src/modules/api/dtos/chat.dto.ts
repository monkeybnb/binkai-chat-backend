import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

export class ChatRequestDto {
  @ApiProperty({
    description: 'The message to send to AI',
    example: 'What is the price of BNB?',
  })
  @IsString()
  message: string;

  @ApiProperty({
    description: 'The thread ID for conversation context',
    example: '123e4567-e89b-12d3-a456-426614174000',
    required: false,
  })
  @IsString()
  @IsOptional()
  threadId?: string;
}

export class ChatResponseDto {
  @ApiProperty({
    description: 'The response from AI',
    example: 'The current price of BNB is $300',
  })
  @IsString()
  response: string;

  @ApiProperty({
    description: 'The thread ID for conversation context',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsString()
  threadId: string;
} 