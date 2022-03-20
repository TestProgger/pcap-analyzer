import { Instance, types } from "mobx-state-tree";

export const RootStore = types.model("RootStore" , {
    date : types.Date
})

export type IRootStore = Instance<typeof RootStore>