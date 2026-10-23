/// <reference types="vite/client" />

import "v86";

declare module "v86" {
  interface V86Options {
    /** Translate the saved guest MAC to the current v86 NIC after restore. */
    mac_address_translation?: boolean;
  }
}
