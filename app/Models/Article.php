<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use OpenApi\Annotations as OA; // Required for OA annotations

/**
 * @OA\Schema(
 *     schema="Article",
 *     type="object",
 *     title="Article Model",
 *     description="Represents an article in the blog.",
 *     required={"title", "category", "content"},
 *     @OA\Property(property="idarticles", type="integer", format="int64", description="Primary key ID of the article", readOnly=true, example=1),
 *     @OA\Property(property="title", type="string", description="Title of the article", example="Understanding Laravel"),
 *     @OA\Property(property="category", type="string", description="Category of the article", example="PHP Frameworks"),
 *     @OA\Property(property="content", type="string", description="Main content of the article", example="Laravel is a web application framework..."),
 *     @OA\Property(property="user_id", type="string", format="uuid", description="UUID of the author (User)", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *     @OA\Property(property="link_picture", type="string", format="url", nullable=true, description="URL to the article's main picture", example="http://example.com/laravel.jpg"),
 *     @OA\Property(property="status", type="string", enum={"draft", "published", "archived"}, description="Status of the article", default="draft", example="published"),
 *     @OA\Property(property="created_at", type="string", format="date-time", description="Creation timestamp", readOnly=true, example="2023-02-01T10:00:00Z"),
 *     @OA\Property(property="updated_at", type="string", format="date-time", description="Last update timestamp", readOnly=true, example="2023-02-01T11:00:00Z"),
 *     @OA\Property(property="author", ref="#/components/schemas/User", description="The author of the article (if loaded)", readOnly=true)
 * )
 *
 * @OA\Schema(
 *     schema="ArticleInput",
 *     type="object",
 *     title="Article Input",
 *     description="Data required to create or update an article.",
 *     required={"title", "category", "content"},
 *     @OA\Property(property="title", type="string", example="My New Article"),
 *     @OA\Property(property="category", type="string", example="Tutorials"),
 *     @OA\Property(property="content", type="string", example="This is the content of my new article."),
 *     @OA\Property(property="link_picture", type="string", format="url", nullable=true, example="http://example.com/new_article.png"),
 *     @OA\Property(property="status", type="string", enum={"draft", "published", "archived"}, example="draft", default="draft")
 * )
 */

class Article extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'articles';

    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'idarticles';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'title',
        'category',
        'content',
        'user_id',
        'link_picture',
        'status',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            // Add casts here if needed, e.g., for status if using enums
        ];
    }

    /**
     * Get the user (author) that owns the article.
     */
    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'iduser');
    }
}
