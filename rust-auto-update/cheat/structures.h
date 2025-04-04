#pragma once
#include <corecrt_math.h>

namespace sdk {
	namespace structs {
		class Vector3
		{
		public:
			Vector3( ) : x( 0.f ) , y( 0.f ) , z( 0.f )
			{

			}

			Vector3( float _x , float _y , float _z ) : x( _x ) , y( _y ) , z( _z )
			{

			}
			~Vector3( )
			{

			}

			float x;
			float y;
			float z;
		};
	}
}