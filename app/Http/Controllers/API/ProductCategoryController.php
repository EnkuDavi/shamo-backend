<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Models\ProductCategory;

class ProductCategoryController extends Controller
{
    public function all(Request $request)
    {
        $id = $request->input('id');
        $limit = $request->input('limit');
        $name = $request->input('name');
        $show_product = $request->input('show_product');

        if($id){
            $category = ProductCategory::with('products')->find($id);
            if($category){
                return ResponseFormatter::success($category, 'Data berhasil diambil');
            }else{
                return ResponseFormatter::error(null, 'Data gagal di ambil', 404);
            }
        }

        $category = ProductCategory::query();
        if($name){
            $category->where('name','like','%'.$name.'%');
        }
        if($show_product){
            $category->with('products');
        }
        if($category){
            return ResponseFormatter::success($category->paginate($limit),'Data berhasil diambil');
        }else{
            return ResponseFormatter::error(null,'Data gagal diambil', 404);
        }
    }
}
