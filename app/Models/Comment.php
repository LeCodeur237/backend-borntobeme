<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use OpenApi\Annotations as OA;

/**
 * @OA\Schema(
 *     schema="Comment",
 *     type="object",
 *     title="Comment Model",
 *     description="Represents a comment on an article, potentially as a reply to another comment.",
 *     required={"id", "content", "user_id", "article_id"},
 *     @OA\Property(property="id", type="integer", format="int64", description="Primary key ID of the comment", readOnly=true, example=1),
 *     @OA\Property(property="content", type="string", description="The content of the comment", example="Great article!"),
 *     @OA\Property(property="user_id", type="string", format="uuid", description="UUID of the user who wrote the comment", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *     @OA\Property(property="article_id", type="integer", format="int64", description="ID of the article this comment belongs to", example=101),
 *     @OA\Property(property="parent_id", type="integer", format="int64", nullable=true, description="ID of the parent comment if this is a reply", example=5),
 *     @OA\Property(property="created_at", type="string", format="date-time", description="Timestamp of comment creation", readOnly=true, example="2023-03-01T10:00:00Z"),
 *     @OA\Property(property="updated_at", type="string", format="date-time", description="Timestamp of last comment update", readOnly=true, example="2023-03-01T10:05:00Z"),
 *     @OA\Property(property="user", ref="#/components/schemas/User", description="The user who wrote the comment", readOnly=true),
 *     @OA\Property(property="article", ref="#/components/schemas/Article", description="The article this comment belongs to", readOnly=true),
 *     @OA\Property(property="replies", type="array", @OA\Items(ref="#/components/schemas/Comment"), description="Replies to this comment", readOnly=true, nullable=true)
 * )
 *
 * @OA\Schema(
 *     schema="CommentInput",
 *     type="object",
 *     title="Comment Input Data",
 *     description="Data required to create or update a comment.",
 *     required={"content"},
 *     @OA\Property(property="content", type="string", example="This is my comment."),
 *     @OA\Property(property="parent_id", type="integer", format="int64", nullable=true, example=10, description="ID of the parent comment if this is a reply. Omit or send null for a top-level comment.")
 * )
 */

class Comment extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'comments';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'content',
        'user_id',
        'article_id',
        'parent_id', // Make parent_id fillable
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            // Add casts here if needed
        ];
    }

    /**
     * Get the user (author) that wrote the comment.
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'iduser');
    }

    /**
     * Get the article that this comment belongs to.
     */
    public function article(): BelongsTo
    {
        return $this->belongsTo(Article::class, 'article_id', 'idarticles');
    }

    /**
     * Get the parent comment (if this comment is a reply).
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(Comment::class, 'parent_id');
    }

    /**
     * Get the replies to this comment.
     */
    public function replies(): HasMany
    {
        return $this->hasMany(Comment::class, 'parent_id')->with(['user', 'replies']); // Eager load user and nested replies
    }
}
