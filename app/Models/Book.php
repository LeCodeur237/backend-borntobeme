<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use OpenApi\Annotations as OA;

/**
 * @OA\Schema(
 *     schema="Book",
 *     type="object",
 *     title="Book Model",
 *     description="Represents a book available for selling.",
 *     required={"idbooks", "title", "author_name", "price", "currency", "user_id", "status"},
 *     @OA\Property(property="idbooks", type="integer", format="int64", description="Primary key ID of the book", readOnly=true, example=1),
 *     @OA\Property(property="title", type="string", description="Title of the book", example="The Great Novel"),
 *     @OA\Property(property="author_name", type="string", description="Name of the book's author", example="John Writer"),
 *     @OA\Property(property="isbn", type="string", nullable=true, description="ISBN of the book", example="978-3-16-148410-0"),
 *     @OA\Property(property="description", type="string", nullable=true, description="Detailed description of the book", example="An amazing story about..."),
 *     @OA\Property(property="price", type="number", format="float", description="Price of the book", example=19.99),
 *     @OA\Property(property="currency", type="string", maxLength=3, description="Currency code for the price (e.g., USD, EUR)", example="USD"),
 *     @OA\Property(property="publication_date", type="string", format="date", nullable=true, description="Date the book was published", example="2023-05-15"),
 *     @OA\Property(property="cover_image_url", type="string", format="url", nullable=true, description="URL to the book's cover image", example="http://example.com/cover.jpg"),
 *     @OA\Property(property="stock_quantity", type="integer", format="int32", description="Number of items in stock", example=100),
 *     @OA\Property(property="status", type="string", enum={"draft", "available", "out_of_stock", "discontinued"}, description="Availability status of the book", example="available"),
 *     @OA\Property(property="user_id", type="string", format="uuid", description="UUID of the user (seller/publisher) who listed the book", example="a1b2c3d4-e5f6-7890-1234-567890abcdef"),
 *     @OA\Property(property="created_at", type="string", format="date-time", description="Timestamp of book creation", readOnly=true, example="2023-01-01T12:00:00Z"),
 *     @OA\Property(property="updated_at", type="string", format="date-time", description="Timestamp of last book update", readOnly=true, example="2023-01-01T12:30:00Z"),
 *     @OA\Property(property="seller", ref="#/components/schemas/User", description="The user who listed the book", readOnly=true)
 * )
 *
 * @OA\Schema(
 *     schema="BookInput",
 *     type="object",
 *     title="Book Input Data",
 *     description="Data required to create or update a book.",
 *     required={"title", "author_name", "price"},
 *     @OA\Property(property="title", type="string", example="My New Book"),
 *     @OA\Property(property="author_name", type="string", example="Jane Author"),
 *     @OA\Property(property="isbn", type="string", nullable=true, example="978-1-23-456789-0"),
 *     @OA\Property(property="description", type="string", nullable=true, example="A brief description of the book."),
 *     @OA\Property(property="price", type="number", format="float", example=29.95),
 *     @OA\Property(property="currency", type="string", maxLength=3, example="USD", default="USD"),
 *     @OA\Property(property="publication_date", type="string", format="date", nullable=true, example="2024-01-01"),
 *     @OA\Property(property="cover_image_url", type="string", format="url", nullable=true, example="http://example.com/my_book_cover.png"),
 *     @OA\Property(property="stock_quantity", type="integer", format="int32", example=50, default=0),
 *     @OA\Property(property="status", type="string", enum={"draft", "available", "out_of_stock", "discontinued"}, example="draft", default="draft")
 * )
 */
class Book extends Model
{
    use HasFactory;

    public const STATUS_DRAFT = 'draft';
    public const STATUS_AVAILABLE = 'available';
    public const STATUS_OUT_OF_STOCK = 'out_of_stock';
    public const STATUS_DISCONTINUED = 'discontinued';


    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'books';

    /**
     * The primary key for the model.
     *
     * @var string
     */
    protected $primaryKey = 'idbooks';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'title',
        'author_name',
        'isbn',
        'description',
        'price',
        'currency',
        'publication_date',
        'cover_image_url',
        'stock_quantity',
        'status',
        'user_id', // Important for associating with the seller
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'price' => 'decimal:2',
        'publication_date' => 'date',
        'stock_quantity' => 'integer',
    ];

    /**
     * Get the user (seller/publisher) that owns the book.
     */
    public function seller(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'iduser');
    }
}
