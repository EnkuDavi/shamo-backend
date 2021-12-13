<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class ProductGallery extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillabel = [
        'products_id',
        'url'
    ];

    public function getAttributeUrl($url)
    {
        return config('app.url') . Storage::url($url);
    }
}
