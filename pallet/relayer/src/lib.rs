// Copyright 2023 Capsule Corp (France) SAS.
// This file is part of Ternoa.

// Ternoa is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Ternoa is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Ternoa.  If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::{
	dispatch::{DispatchResultWithPostInfo, GetDispatchInfo},
	pallet_prelude::*,
	traits::{ StorageVersion, UnfilteredDispatchable},
};
use frame_system::pallet_prelude::*;
use sp_std::prelude::*;

const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// A sudo-able call.
		type RuntimeCall: Parameter
			+ UnfilteredDispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo;

		// Someone who can call the mandate extrinsic.
		type ExternalOrigin: EnsureOrigin<Self::RuntimeOrigin>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

    #[pallet::storage]
	pub type Relayer<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// #[pallet::weight({
		// 	let dispatch_info = call.get_dispatch_info();
		// 	(dispatch_info.weight, dispatch_info.class)
		// })]
		#[pallet::weight(10000000)]
		pub fn register_relayer(
			origin: OriginFor<T>,
			address: T::AccountId,
		) -> DispatchResult {
			T::ExternalOrigin::ensure_origin(origin)?;

            Relayer::<T>::mutate(|user| {
                *user = Some(address.clone());
            });

			Self::deposit_event(Event::NewRegistration { address, role: "relayer".as_bytes().to_vec() });

			Ok(())
		}

		#[pallet::weight(10000000)]
        pub fn update_relayer(
			origin: OriginFor<T>,
			address: T::AccountId,
		) -> DispatchResult {
			T::ExternalOrigin::ensure_origin(origin)?;

            // Relayer::try_mutate_exists(|user_opt| {
			// 	if let Some(user) => user_opt {
			// 		user = address;
			// 	}
            // });

			Self::deposit_event(Event::NewRegistration { address, role: "relayer".as_bytes().to_vec() });

			Ok(())
		}

		#[pallet::weight(10000000)]
		pub fn remove_relayer(
			origin: OriginFor<T>,
			address: T::AccountId,
		) -> DispatchResult {
			T::ExternalOrigin::ensure_origin(origin)?;

            // Relayer::try_mutate_exists(|user_opt| {
            //     user = address;
            // });

			Self::deposit_event(Event::NewRegistration { address, role: "relayer".as_bytes().to_vec() });

			Ok(())
		}
	}
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A root operation was executed, show result
	    NewRegistration { address: T::AccountId, role: Vec<u8> },
	}
}